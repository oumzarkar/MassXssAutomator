<h1 style="font-size: 36px;">MassXssAutomator</h1>
Intigration script for my fellow lazy bug hunters
uses assetfinder,katana,httpx and xss_vibes to find xss vulnerabilites in websites
utilizes maximum available resouces 
suitable for very large scope targets
just run 
python3 massxssautomator.py

<pre><code class="language-bash">
# Command 1
$ your_command_here

# Command 2
$ another_command_here
</code></pre>

  
<p style="font-size: 18px;">INSTALLATION</p>
1)make sure you have go installed with version go1.22
  `wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz`
  `rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz`
  `export PATH=$PATH:/usr/local/go/bin`
  `go version`
2)Install katana
  `go install github.com/projectdiscovery/katana/cmd/katana@latest`
  `cp ~/go/bin/katana /usr/bin/`
  `katana`
3)Install httpx
  `apt remove python3-httpx`
  `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
  `cp ~/go/bin/httpx /usr/bin/`
  `httpx`
4)Install assetfinder
  `apt install assetfinder`
  
  

  


