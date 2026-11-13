<p style="align: left; margin: 0; padding: 0;">
  <img
    src="images/banner.png"
    alt="slapp-rs banner"
    width="300em"
    style="max-width: 100%; height: auto"
  />
  <br />
  <sub>Banner artist: <a href="https://x.com/LophasiaA">LophasiaA</a></sub>
</p>

# slapp-rs

Framework for building MitM applications.

Skip the nasty stuff. Get visibility into the network stack.

> [!IMPORTANT]  
> This project is AI-free. The code is either handwritten or copied from the internet (with references provided). However, AI might be used for architectural design and rubber ducking.

## Known issues

**Interfaces with MTU 65535**

If an interface has the MTU set to 65535 (like loopback has), NFQUEUE [will only provide 65531 bytes at most](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html). The solution is to decrease the MTU or change the interface.
