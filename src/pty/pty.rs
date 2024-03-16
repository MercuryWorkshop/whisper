use std::{sync::Arc, vec};

use bytes::Bytes;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader, BufWriter},
    sync::Mutex,
};

use super::error::PtyError;

pub struct PtyInterface {
    pty: Arc<File>,
    path: String,
    pty_tx: tokio::sync::mpsc::Sender<Bytes>,
    pty_rx: Arc<Mutex<tokio::sync::mpsc::Receiver<Bytes>>>,
    interface_tx: tokio::sync::mpsc::Sender<Bytes>,
    interface_rx: Arc<Mutex<tokio::sync::mpsc::Receiver<Bytes>>>,
}

// TODO: This needs a serious rewrite.
impl PtyInterface {
    pub async fn new(path: String) -> Result<PtyInterface, PtyError> {
        let pty = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .await?,
        );
        let (pty_tx, pty_rx) = tokio::sync::mpsc::channel(1500);
        let (interface_tx, interface_rx) = tokio::sync::mpsc::channel(1500);
        Ok(PtyInterface {
            pty,
            path,
            pty_tx,
            pty_rx: Arc::new(Mutex::new(pty_rx)),
            interface_tx,
            interface_rx: Arc::new(Mutex::new(interface_rx)),
        })
    }

    pub async fn write(&self, data: Bytes) -> Result<(), Box<dyn std::error::Error>> {
        let tx = self.interface_tx.clone();
        tx.send(data).await?;
        Ok(())
    }

    pub async fn read(&mut self) -> Result<Bytes, Box<dyn std::error::Error>> {
        let mut rx = self.pty_rx.lock().await;
        Ok(rx.recv().await.unwrap())
    }

    pub fn get_path(&self) -> String {
        self.path.clone()
    }

    pub(crate) async fn read_from_input(&self) {
        let file = Arc::clone(&self.pty);
        let mut input_rx = self.interface_rx.lock().await;
        while let Some(data) = input_rx.recv().await {
            println!("Received data: {:?}", data);
            let mut file_writer = BufWriter::new(file.try_clone().await.unwrap());
            if let Err(err) = file_writer.write_all(&data).await {
                eprintln!("Error writing to file: {}", err);
            }
        }
    }

    pub(crate) async fn write_to_output(&self) {
        let file = Arc::clone(&self.pty);
        let output_tx = self.pty_tx.clone();
        let mut file_reader = BufReader::new(file.try_clone().await.unwrap());
        let mut buffer = vec![0u8; 1500];
        loop {
            buffer.clear();
            if let Err(err) = file_reader.read_to_end(buffer.as_mut()).await {
                eprintln!("Error reading from file: {}", err);
                break;
            }
            if !buffer.is_empty() {
                if let Err(err) = output_tx.send(Bytes::from(buffer.clone())).await {
                    eprintln!("Error sending data through output channel: {}", err);
                    break;
                }
            }
        }
    }
}
