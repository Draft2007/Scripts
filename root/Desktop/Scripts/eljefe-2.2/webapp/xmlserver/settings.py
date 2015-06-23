#settings for xml server
LOGHOST = "0.0.0.0"
LOGPORT = 5555

#logging options
LOGGING_FILENAME="ElJefeXMLServer.log"
LOGGING_LEVEL="INFO"

#be sure to use your own certs
KEYFILE='certs/server.key'
CERTFILE='certs/server.pem'
CA_CERTFILE='certs/cacert.pem'

# Email alert settings
ENABLE_EMAIL_ALERTS = False
EMAIL_ACCOUNT = "youraccount@domainthatshouldreallybeset.com" 
SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 25
