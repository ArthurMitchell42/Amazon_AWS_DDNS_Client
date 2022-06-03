# Amazon_AWS_DDNS_Client
The Amazon AWS DDNS Client

## History
<table>
<thead>
<tr bgcolor="lightblue"><th align="center">Date</th>
<th>Version</th>
<th>Notes</th>
</tr>
</thead>
<tbody><tr>
<td align="left">8/7/21</td>
<td align="left">2.0.0.2</td>
<td align="left">
  <ol>
  <li>Added support for docker health checking, if needed, using a "touched" file</li>
  <li>Added support for an environment variable, HEALTHCHECK_HEARTBEAT_FILE, defining the file path and name.</li>
  <li><b>Note, a failure to go round the main program loop or a configuration issue resulting in an issue updating a domain record will prevent the health check file from being "touched". Be mindful of this if your system is set to restart a conatiner that marks itself as unhealthy as the solution may be to check the log to find a logical issue in the AWS configuration which caused the condition rather than just restarting it.</b></li>
  <li>Added Config parameters Sleep_Time_Initial_Autherisation and Sleep_Time_Inter_Domain to control the hit rate on AWS</li>
  <li>Changes to support re-reading a config file if it's edited while the app is running. This removes the need to re-start the app/container if the configuration is changed. This is intended to harden the system and lower maintainance.</li>
  </ol>
</td>
</tr>
</tbody></table>

# Credentials file
The AWS credentials file needs to be present on your system. Dafult locations where the file will be found are:<br>

Default locations: <br>
Linux: <br>
> ~/.aws/credentials <br>

Windows: <br>
> C:\Users\USERNAME\\.aws\credentials <br>

Using environment variables <br>
> AWS_ACCESS_KEY_ID = XXXXXXXXXXXXXXXXXXXX <br>
> AWS_SECRET_ACCESS_KEY = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY <br>

<h2>Preparation and Application Setup</h2>
<p>
The following steps should be taken when setting up this container:<br>
Install the BOTO3 package:<br>
On Windows <br>
> pip install boto3 <br>
(In an admin cmd shell) <br>

<h3>Prepair an AWS key</h3>
<ol>
  <li>Get an AWS IAM key pair</li>
  <li>Enable permissions to access Route53 (and only Route53) for the key</li>
</ol>

<h3>Setup the AWS Route53 Zones and records</h3>
<ol start="3">
  <li>Have a functional hosted zone for your domain</li>
  <li>If you want one specific URL to point to your IP set up a single A-Record such as <b><i>home.yourdomain.com</b></i></li>
  <li>If you want to use reverse proxy to have a number of sub-domain URLs pointing to a number of resources on your IP set up address then set up your records as listed below.</li>
</ol>

<h3>Setup the app</h3>
<ol start="6">
  <li>Create the configuration directory or use the working directory of the app.</li>
  <li>Create the .ini file with the nessesary information.</li>
  <li>Add the credentials file to your system or set the environment variables and start.</li>
</ol>
</p>

<h2>The Configuration File</h2>
<p>
A text file named <b><i>AWS_Route53_DDNS.ini</b></i> should be created in the <b><i>/config</b></i> mapped directory. This sets all the options for the program.<br>
The log file is created in the same directory with the name <b><i>AWS_Route53_DDNS.log</b></i> and this file will rotate when it reaches 100KB with up to 5 logs named <b><i>AWS_Route53_DDNS.log.1</b></i>, <b><i>AWS_Route53_DDNS.log.2</b></i> etc. 
</p>

<h3>Example Configuration File</h3>
<tt><pre>
[Domains]
yourdomain.com = home.yourdomain.com
yourdomain.eu = yourdomain.eu
yourdomain.click = yourdomain.click

[Defaults]
Update_Interval = 3600
Exception_Interval = 300
; Log_Level options are: Debug Info Warning Error Critical
Log_Level_Logfile = Info 
Log_Level_Console = Warning 
TTL = 3600
Sleep_Time_Initial_Autherisation = 1
Sleep_Time_Inter_Domain = 1
</tt></pre>

<h2>The Configuration File Parameters</h2>
<p>
The parameters for the configuration file are as follows.
<br>
<table>
<thead>
<tr><th align="center">Parameter</th>
<th>Status</th>
<th>Default</th>
<th>Function</th>
</tr>
</thead>
<tbody><tr>
<tr>
<tr>
<td align="left"><b>[Domains] Section</b></td>
<td>Required</td>
<td></td>
<td>Any (resonable) number of lines can be included here.</td>
</tr>
<tr>
<td align="left">Hosted zone name</td>
<td></td>
<td></td>
<td>The text name of the hosted zone (also called the domain name) <b>without</b> the trailing dot '.' that is often used to demark them.</td>
</tr>
<tr>
<td align="left">Record name</td>
<td></td>
<td></td>
<td>This is the value for the corrosponding hosted zone (domain) name. See below for options on this.</td>
</tr>
<tr>
<td align="left"><b>[Defaults] Section</b></td>
<td>Optional</td>
<td></td>
<td></td>
</tr>
<tr>
<td align="left">Update_Interval</td>
<td>Optional</td>
<td>3600</td>
<td>The interval between checking the external IP to see if the address has changed.</td>
</tr>
<tr>
<td align="left">Exception_Interval</td>
<td>Optional</td>
<td>Update_Interval value</td>
<td>The checking interval after an error in obtaining the external IP or in obtailing the AWS hosted domain connection. You may wish to set this value lower than the usual update interval to resume correct mapping after a disruption to the IP address.</td>
</tr>
<tr>
<td align="left">Log_Level_Logfile</td>
<td>Optional</td>
<td>Warning</td>
<td>Sets the detail and level for the file stored in the /config mapping</td>
</tr>
<tr>
<td align="left">Log_Level_Console</td>
<td>Optional</td>
<td>Error</td>
<td>Sets the detail and level for the console (docker log)</td>
</tr>
<tr>
<td align="left"></td>
<td></td>
<td></td>
<td>Logging levels options are :- Critical Error Warning Info Debug</td>
</tr>
<tr>
<td align="left">TTL</td>
<td>Optional</td>
<td>3600</td>
<td>The time-to-live value for your entries in seconds. 1-2 hours is usual, less than 5 minutes is not recomended. Values below 60 are ignored and set to 60 seconds.</td>
</tr>
<tr>
<td align="left">Sleep_Time_Inter_Domain </td>
<td>Optional</td>
<td>1</td>
<td>The time to pause between consucutive domain interrogations.</td>
</tr>
<tr>
<td align="left">Sleep_Time_Initial_Autherisation</td>
<td>Optional</td>
<td>1</td>
<td>The time to pause between autherisation and domain interrogations.</td>
</tr>  
</tbody></table>
</p>
<p>The example file above shows two main options for configuring an address. The first updates a specific A record in the hosted domain so that <b><i>home.yourdomain.com</b></i> is given the external IP address. This is the most simple case and you must create an A-Record with the name <b><i>home.yourdomain.com</b></i> in AWS before it can be updated.</p>
<p>
The second and third lines show a more flexible option that would allow you to create multiple sub-domain mappings to resources within your network using reverse proxy. To make this work you must create an A-Record within you hosted zone (domain) called <b><i>yourdomain.click</b></i> and then a second A-Record called <b><i>*.yourdomain.click</b></i> that has a value of <b><i>yourdomain.click</b></i>. This will cause any DNS request for sub-domains of this address such as <b><i>voip.yourdomain.click</b></i> or <b><i>sonarr.yourdomain.click</b></i> to be mapped through to the IP address set up in the <b><i>yourdomain.click</b></i> A-Record.
</p>

<p><b>If you find this container useful then please consider</b> <a href="https://www.paypal.com/donate?hosted_button_id=N6F4E9YCD5VC8">buying me a coffee by following this link or scanning the QR below.</a> :)</p>

<a href="https://www.paypal.com/donate?hosted_button_id=N6F4E9YCD5VC8"> <img src="http://www.ajwm.uk/dockerdonate.jpg" alt="Please consider donating" width="120" height="120"> </a>
