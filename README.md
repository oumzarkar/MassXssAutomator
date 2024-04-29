<h1 style="font-size: 36px;">MassXssAutomator</h1>
<p>Intigration script for my fellow lazy bug hunters</p>
<p>uses assetfinder,katana,httpx and xss_vibes to find xss vulnerabilites in websites
<p>utilizes maximum available resouces </p>
<p>suitable for very large scope targets</p>
<p>just run </p>

<pre><code class="language-bash">python3 massxssautomator.py</code></pre>

  
<p style="font-size: 18px;">INSTALLATION</p>
1)make sure you have go installed with version go1.22
  <pre><code class="language-bash">wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz</code></pre>
  <pre><code class="language-bash">rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz</code></pre>    
  <pre><code class="language-bash">export PATH=$PATH:/usr/local/go/bin</code></pre>    
2)Install katana
  <pre><code class="language-bash">go install github.com/projectdiscovery/katana/cmd/katana@latest</code></pre>  

  <pre><code class="language-bash">cp ~/go/bin/katana /usr/bin/</code></pre>    
  <pre><code class="language-bash">katana</code></pre>
3)Install httpx
  <pre><code class="language-bash">apt remove python3-httpx</code></pre>
  <pre><code class="language-bash">go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest</code></pre>
  <pre><code class="language-bash">cp ~/go/bin/httpx /usr/bin/</code></pre>
  <pre><code class="language-bash">httpx</code></pre>
4)Install assetfinder
  <pre><code class="language-bash">apt install assetfinder</code></pre>
5)and Lastly 
<pre><code class="language-bash">pip install -r requirements</code></pre>
  
  

  


