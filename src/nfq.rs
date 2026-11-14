use std::error::Error;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::unix::AsyncFd;

use crate::{
    ApplicationDataSlappHandler, Ipv4Type, NetworkSlappHandler, NetworkSlappSpy, PayloadWrapper,
    SlappInterceptVerdict, SlappIpv4, SlappTcp, TransportSlappSpy,
};

impl PayloadWrapper for nfq::Message {
    fn get_payload_mut(&mut self) -> &mut [u8] {
        self.get_payload_mut()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SlappNfqNetOptions {
    pub queue_num: u16,
    pub max_queue_len: Option<u32>,
}

impl SlappNfqNetOptions {
    pub fn open_from_handler<NetHandler>(
        &self,
        net_handler: NetHandler,
    ) -> Result<SlappNfqNet<NetHandler>, Box<dyn Error>>
    where
        NetHandler: NetworkSlappHandler<nfq::Message>,
    {
        SlappNfqNet::new_from_handler(self, net_handler)
    }

    pub fn open<NetHandler>(&self) -> Result<SlappNfqNet<NetHandler>, Box<dyn Error>>
    where
        NetHandler: NetworkSlappHandler<nfq::Message> + Default,
    {
        SlappNfqNet::new_from_handler(self, NetHandler::default())
    }
}

pub struct SlappNfqNet<NetHandler>
where
    NetHandler: NetworkSlappHandler<nfq::Message>,
{
    pub queue: nfq::Queue,
    pub net_handler: NetHandler,
}

impl<NetHandler> SlappNfqNet<NetHandler>
where
    NetHandler: NetworkSlappHandler<nfq::Message>,
{
    /// Creates a new `Self` instance from `NetHandler`.
    ///
    /// # Arguments
    ///
    /// * `opts` - Configuration options.
    /// * `net_handler` - An instance that handles network packets.
    pub fn new_from_handler(
        opts: &SlappNfqNetOptions,
        net_handler: NetHandler,
    ) -> Result<Self, Box<dyn Error>> {
        let mut queue = nfq::Queue::open()?;
        queue.bind(opts.queue_num)?;
        queue.set_nonblocking(true);
        queue.set_copy_range(opts.queue_num, u16::MAX)?;
        if let Some(max_queue_len) = opts.max_queue_len {
            queue.set_queue_max_len(opts.queue_num, max_queue_len)?;
        }

        Ok(Self { queue, net_handler })
    }

    async fn get_next_msg(
        &mut self,
        async_fd: &mut AsyncFd<RawFd>,
    ) -> Result<nfq::Message, Box<dyn Error + Send + Sync>> {
        loop {
            let mut guard = async_fd.readable().await?;

            match self.queue.recv() {
                Ok(msg) => {
                    return Ok(msg);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        }
    }

    pub fn get_next_msg_blocking(&mut self) -> Result<nfq::Message, Box<dyn Error>> {
        match self.queue.recv() {
            Ok(msg) => Ok(msg),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                panic!("queue would block");
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn verdict(
        &mut self,
        msg: nfq::Message,
        async_fd: &mut AsyncFd<RawFd>,
    ) -> Result<(), Box<dyn Error>> {
        let mut _guard = async_fd.writable().await?;

        match self.queue.verdict(msg) {
            Ok(msg) => Ok(msg),
            Err(err) => Err(err.into()),
        }
    }

    pub fn verdict_blocking(&mut self, msg: nfq::Message) -> Result<(), Box<dyn Error>> {
        Ok(self.queue.verdict(msg)?)
    }

    async fn wait_for_verdict(
        &mut self,
        running: Arc<AtomicBool>,
        msg: nfq::Message,
        async_fd: &mut AsyncFd<RawFd>,
    ) -> Result<(), Box<dyn Error>> {
        tokio::select! {
            ret = self.verdict(msg, async_fd) => {
                ret?;
            },
            _ = async move {
                while running.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            } => (),
        }

        Ok(())
    }

    pub async fn intercept(
        &mut self,
        running: Arc<AtomicBool>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // SAFETY: The fd owned by queue is valid as long as self.queue is alive
        let mut async_fd = unsafe { AsyncFd::register(self.queue.as_raw_fd())? };

        while running.load(Ordering::SeqCst) {
            let running_clone = running.clone();
            let while_running = async move {
                while running_clone.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            };
            let msg = tokio::select! {
                msg = self.get_next_msg(&mut async_fd) => {
                    msg
                },
                _ = while_running => {
                    // Trigger when `running` is set to false
                    return Ok(());
                },
            }?;

            {
                let payload_len = msg.get_payload().len();
                let original_len = msg.get_original_len();
                if payload_len != original_len {
                    println!("len / original: {} / {}", payload_len, original_len);
                    panic!("Packet was truncated");
                }
            }

            let verdicts = self.net_handler.on_payload(msg);

            for vd in verdicts {
                let msg = match vd {
                    SlappInterceptVerdict::Accept(mut msg) => {
                        msg.set_verdict(nfq::Verdict::Accept);

                        msg
                    }
                    SlappInterceptVerdict::Drop(mut msg) => {
                        msg.set_verdict(nfq::Verdict::Drop);

                        msg
                    }
                    _ => {
                        continue;
                    }
                };

                self.wait_for_verdict(running.clone(), msg, &mut async_fd)
                    .await
                    .unwrap();
            }
        }

        Ok(())
    }
}

pub type SlappNfqIpv4Tcp<AH, NetSpy, TSpy> =
    SlappNfqNet<SlappIpv4<SlappTcp<AH, TSpy, Ipv4Type, nfq::Message>, NetSpy, nfq::Message>>;

impl<AH, NetSpy, TSpy> SlappNfqIpv4Tcp<AH, NetSpy, TSpy>
where
    AH: ApplicationDataSlappHandler,
    NetSpy: NetworkSlappSpy,
    TSpy: TransportSlappSpy,
{
    pub fn new_from_handlers(
        opts: &SlappNfqNetOptions,
        app_handler: AH,
        net_spy: NetSpy,
        transport_spy: TSpy,
    ) -> Result<Self, Box<dyn Error>> {
        let tcp = SlappTcp::new_from(app_handler, transport_spy);
        let ip = SlappIpv4::new(tcp, net_spy);

        SlappNfqNet::new_from_handler(opts, ip)
    }
}

impl<AH, NetSpy, TSpy> SlappNfqIpv4Tcp<AH, NetSpy, TSpy>
where
    AH: ApplicationDataSlappHandler + Default,
    NetSpy: NetworkSlappSpy + Default,
    TSpy: TransportSlappSpy + Default,
{
    pub fn new(opts: &SlappNfqNetOptions) -> Result<Self, Box<dyn Error>> {
        let app_handler = AH::default();
        let net_spy = NetSpy::default();
        let transport_spy = TSpy::default();
        Self::new_from_handlers(opts, app_handler, net_spy, transport_spy)
    }
}
