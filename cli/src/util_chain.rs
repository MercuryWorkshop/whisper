// taken from tokio io util
#![allow(clippy::pedantic, clippy::all)]

use std::{
	fmt, io,
	pin::Pin,
	task::{Context, Poll},
};

use futures_util::ready;
use pin_project_lite::pin_project;
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

pin_project! {
	pub struct Chain<T, U> {
		#[pin]
		first: T,
		#[pin]
		second: U,
		done_first: bool,
	}
}

pub fn chain<T, U>(first: T, second: U) -> Chain<T, U>
where
	T: AsyncRead,
	U: AsyncRead,
{
	Chain {
		first,
		second,
		done_first: false,
	}
}

impl<T, U> fmt::Debug for Chain<T, U>
where
	T: fmt::Debug,
	U: fmt::Debug,
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Chain")
			.field("t", &self.first)
			.field("u", &self.second)
			.finish()
	}
}

impl<T, U> AsyncRead for Chain<T, U>
where
	T: AsyncRead,
	U: AsyncRead,
{
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let me = self.project();

		if !*me.done_first {
			let rem = buf.remaining();
			ready!(me.first.poll_read(cx, buf))?;
			if buf.remaining() == rem {
				*me.done_first = true;
			} else {
				return Poll::Ready(Ok(()));
			}
		}
		me.second.poll_read(cx, buf)
	}
}

impl<T, U> AsyncBufRead for Chain<T, U>
where
	T: AsyncBufRead,
	U: AsyncBufRead,
{
	fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
		let me = self.project();

		if !*me.done_first {
			match ready!(me.first.poll_fill_buf(cx)?) {
				[] => {
					*me.done_first = true;
				}
				buf => return Poll::Ready(Ok(buf)),
			}
		}
		me.second.poll_fill_buf(cx)
	}

	fn consume(self: Pin<&mut Self>, amt: usize) {
		let me = self.project();
		if !*me.done_first {
			me.first.consume(amt)
		} else {
			me.second.consume(amt)
		}
	}
}
