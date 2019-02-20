#!/usr/bin/env python
# -*- coding: utf-8 -*-


# Get system type
import platform
SYSTEM = platform.system()

LOCKFILE = 'PRIANA.LOCK'

# System related imports (aux)
import os, os.path
from os.path import expanduser

import sys
if SYSTEM == 'Linux':
    import pwd
sys.path.append( os.path.join( 'bin', 'instantclient' ) )
from glob import glob
from time import sleep
from base64 import b64encode, b64decode, urlsafe_b64decode, urlsafe_b64encode
import re
import subprocess
from datetime import datetime, timedelta
import errno
import time
import shlex

PIPE = subprocess.PIPE

if subprocess.mswindows:
    from win32file import ReadFile, WriteFile
    from win32pipe import PeekNamedPipe
    import msvcrt
else:
    import select
    import fcntl


# SPADE related imports
from spade.Agent import Agent
from spade.Behaviour import OneShotBehaviour, PeriodicBehaviour, EventBehaviour, ACLTemplate, MessageTemplate
from spade.AID import aid
from spade.ACLMessage import ACLMessage

from runspade import main
from configure import generateCode

from Crypto.Cipher import AES


# Look here for windows installation:
# https://github.com/deanmalmgren/textract/issues/111
# http://textract.readthedocs.io/en/latest/installation.html
if SYSTEM != 'Windows':
    import textract

def extract( file, ext=None ):
    if SYSTEM == 'Windows':
        # run extract.exe
        enc = sys.getfilesystemencoding()
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        prog = [ 'extract.exe', file ]
        # TODO: Make mime happen for windows
        '''if ext:
            try:
                mime = TYPES2MIMES[ ext ]
                prog.append( mime )
            except:
                print 'Unknown extension: ', ext'''
        env = os.environ.copy()
        env[ "PATH" ] = r".\bin\antiword;.\bin\pdftools;.\bin\Tesseract-OCR;" + env[ "PATH" ]
        proc = subprocess.Popen( prog, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, startupinfo=startupinfo )
        proc.stdin.close()
        output, err = proc.communicate()
        # Comment on code bellow: I have no idea what I am doing (https://uproxx.com/viral/i-have-no-idea-what-im-doing-dog-memes/)
        # I just hate Unicode! This is probably the only reason I will change to Py3 (which I also hate because of print, ugh...)
        # The code now works for some reason. Getting back to my life again...
        if 'Error: File at path' in err and 'does not exist' in err:
            #print '='*100
            #print "ERROR", err
            #print "OUTPUT", output
            try:
                prog = [ 'extract.exe', file.decode( 'utf-8' ).encode( sys.getfilesystemencoding() ) ]
                proc = subprocess.Popen( prog, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, startupinfo=startupinfo )
                proc.stdin.close()
                output, err = proc.communicate()
            except Exception as e:
                #print "DOESNT WORK ANYWAY BECAUSE", e
                try:
                    file = u' '.join( [ file ] ).strip()
                    prog = [ 'extract.exe', file ]
                    proc = subprocess.Popen( prog, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, startupinfo=startupinfo )
                    proc.stdin.close()
                    output, err = proc.communicate()
                except Exception as e1:
                    #print 'DOESNT WORK EITHER BECAUSE', e1
                    try:
                        file = u' '.join( [ file ] ).strip()
                        prog = [ 'extract.exe', file.decode( 'utf-8' ).encode(sys.getfilesystemencoding()) ]
                        proc = subprocess.Popen( prog, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, startupinfo=startupinfo )
                        proc.stdin.close()
                        output, err = proc.communicate()
                    except Exception as e2:
                        #print 'IM RUNNING OUT OF IDEAS, WTF!!!', e2
                        pass
        #print '*'*50
        #try:
        #    print file.decode( 'utf-8' )
        #except:
        #    print 'Nja'
        #print file
        #print '-'*50
        #print output[ 0:100 ]
        #print '*'*50
        return output
    else:
        if ext:
            return textract.process( file, extension=ext )
        else:
            return textract.process( file )
       
# Internationalization
import gettext
# TODO: Adjust this:
#gettext.bindtextdomain( APPNAME, LANGPATH )
#gettext.textdomain( APPNAME )
_ = gettext.gettext

# JSON related imports
from json import dumps, loads

# ZODB related imports
from persistent import Persistent
from persistent.list import PersistentList
from persistent.mapping import PersistentMapping
from ZODB import FileStorage, DB
from ZEO.ClientStorage import ClientStorage
import transaction

def open_fs( zfile ):
    ''' Open file storage in given file path.
        Returns connection to db.'''
    storage = FileStorage.FileStorage( zfile )
    db = DB( storage )
    conn = db.open()
    return storage, db, conn

def open_cs( zhost, zport ):
    ''' Open client storage on given host and port.
        Returns connection to db.'''
    storage = ClientStorage( ( zhost, zport ) )
    db = DB( storage )
    conn = db.open()
    return storage, db, conn


# Magic
import magic
if SYSTEM == 'Windows':
    mime_extract = magic.Magic( magic_file='magic.mgc', mime=True )
else:
    mime_extract = magic

def get_mime( fl ):
    if SYSTEM == 'Windows':
        try:
            mime = mime_extract.from_file( fl )
            if 'cannot open' in mime:
                mime = mime_extract.from_file( fl.decode( 'utf-8' ) )
        except:
            mime = 'unknown'
        return mime
    else:
        return mime_extract.from_file( fl, mime=True )
# NLP related imports
import nltk
nltk.data.path = [ 'libs' ]

if not os.path.isdir( 'libs' ):
    nltk.download( 'punkt', download_dir='libs' )
    nltk.download( 'averaged_perceptron_tagger', download_dir='libs' )
    nltk.download( 'maxent_ne_chunker', download_dir='libs' )
    nltk.download( 'words', download_dir='libs' )
from nameparser.parser import HumanName

# SQLAlchemy related imports
import sqlalchemy
from sqlalchemy import create_engine
import pyodbc

# Regular expressions
email_re = re.compile( r'[\w\.-]+@[\w\.-]+\.\w+' )
oib_re = re.compile( r'[^0-9]([0-9]{11})[^0-9]' )
jmbg_re = re.compile( r'[^0-9]([0-9]{13})[^0-9]' )
ip_re = re.compile( r'((?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))' ) # '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' )
tel_re = re.compile( r'(\+[0-9]{1,3}\.[0-9]{4,14}(?:x.+)?)|(\+(?:[0-9].?){6,14}[0-9])|(?:[^0-9]((?:0[0-9]{1,2}[/ ]?(?:[0-9 -]){6,10}))[^0-9])' )
# TODO: Add these
mac_re = re.compile( r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})' )
gps_re = re.compile( r'[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)' )
card_re = re.compile( r'(\b[4|5|6]\d{3}[\s-]?(\d{4}[\s-]?){2}\d{1,4}\b)|(\b\d{4}[\s-]?\d{6}[\s-]?\d{5}\b)' )


# Maximum number of datasets processed in parallel
import multiprocessing
MAXLEN = multiprocessing.cpu_count()
from multiprocessing import Process
import psutil


# TODO: Put this into config
USERNAME = 'testuser'
PASSWORD = 'secret'
SERVER = '127.0.0.1'
FILETYPES = [ 'csv', 'doc', 'docx', 'eml', 'epub', 'gif', 'jpg', 'jpeg', 'json', 'html', 'htm', 'mp3', 'msg', 'odt', 'ogg', 'pdf', 'png', 'pptx', 'ps', 'rtf', 'tiff', 'tif', 'txt', 'wav', 'xlsx', 'xls', 'mdb', 'rtf', 'html' ]
MIMETYPES = [ 'text/csv', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'message/rfc822', 'application/epub+zip', 'image/gif', 'image/jpeg', 'image/jpeg', 'application/json', 'text/html', 'text/html', 'audio/mpeg', 'message/rfc822', 'application/vnd.oasis.opendocument.text', 'audio/ogg', 'application/pdf', 'image/png', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/postscript', 'application/rtf', 'image/tiff', 'image/tiff', 'text/plain', 'audio/wave', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-excel', 'application/x-msaccess', 'text/rtf', 'text/xml' ]
VBOXES = [ 'ovf', 'ova', 'box', 'vmdk', 'vdi', 'vhd', 'img', 'raw', 'iso', 'zip', 'rar', 'tar', '7z' ]


MIMES2TYPES = dict( zip( MIMETYPES, FILETYPES ) )
TYPES2MIMES = dict( zip( FILETYPES, MIMETYPES ) )
del MIMES2TYPES[ 'application/x-msaccess' ]

DBTYPES = [ 'SQLite', 'MS Access', 'PostgreSQL', 'MySQL', 'MS SQL Server', 'Oracle', 'ODBC' ]
DBTYPES.sort()

ERRORS = []

KEYWORDS = [ 'oib', 'ime', 'prezime', 'email', 'spol', 'nacionalnost', 'dravljanstvo', 'drzavljanstvo', 'tel', 'telefonski', 'ip', 'adresa', 'kuni broj', 'kucni broj', 'ulica', 'potanski broj', 'postanski broj', 'e-mail', 'name', 'surname', 'telephone', 'address', 'gender', 'nationality', 'citizenship', 'mac', 'gps', 'rfid', 'bank', 'raun', 'racun' ]

EDUCATION_KEYWORDS = [ 'vss', 'mr.sc.', 'mr. sc.', 'mag.', 'bacc.', 'prof.', 'doc.', 'dr.', 'ing.' ]
SEXUAL_ORIENTATION_KEYWORDS = [ 'heteroseks', 'homoseks', 'biseks', 'transrod', 'queer', 'gej', 'lezb', 'gay', 'heterosex', 'homosex', 'bisex', 'lesb', 'transgender' ]

LINUX_ROOT = '/media/home2/Dropbox/' # '/home/markus'
WINDOWS_ROOT = 'C:\\Users\\Marinela'

NAMES_TRESHOLD = 2
LOCATIONS_TRESHOLD = 2
KEYWORDS_TRESHOLD = 4
MAX_TEXT_LEN = 10000 # in characters
MAX_FILE_LEN = 1024 * 1024 * 20 # 20 MB for now, maybe increase this later!

import tempfile

DBFOLDER = tempfile.mkdtemp()
DBFILE = os.path.join( DBFOLDER, 'pa.fs' )
REPORT_FILE = ''

PARSED = 0
DONE = False
NUM_FILES = 0
NUM_DBS = 0

import face_recognition

def recognize( image ):
    img = face_recognition.load_image_file( image )
    face_locations = face_recognition.face_locations( img, number_of_times_to_upsample=0, model='hog' )
    if face_locations:
        return face_locations
    else:
        face_locations = face_recognition.face_locations( img, number_of_times_to_upsample=0, model='cnn' )
        return face_locations


def get_cpu_id():
    if SYSTEM == 'Windows':
        unique = subprocess.check_output( 'wmic csproduct get UUID'.split(), **subprocess_args( False ) ).split()[ 1 ]
        username = os.getenv( 'username' )
    elif SYSTEM == 'Linux':
        unique = subprocess.check_output( 'cat /var/lib/dbus/machine-id'.split() ).split()[ 0 ]
        username = pwd.getpwuid( os.getuid() )[ 0 ]
    else:
        unique = 'UNSUPPORTED' # TODO: get equivalent for mac
        username = pwd.getpwuid( os.getuid() )[ 0 ]
    return unique, username

def get_human_names( text ):
    tokens = nltk.tokenize.word_tokenize( text )
    pos = nltk.pos_tag( tokens )
    sentt = nltk.ne_chunk( pos, binary = False )
    person_list = []
    person = []
    name = ""
    for subtree in sentt.subtrees( filter=lambda t: t.label() == 'PERSON' ):
        for leaf in subtree.leaves():
            person.append( leaf[ 0 ] )
        if len( person ) > 0: #1 to avoid grabbing lone surnames
            for part in person:
                name += part + ' '
            if name[:-1] not in person_list:
                person_list.append(name[:-1])
            name = ''
        person = []

    return ( person_list )

def get_locations( text ):
    locations = []
    for chunk in nltk.ne_chunk( nltk.pos_tag( nltk.word_tokenize( text ) ) ):
        if hasattr( chunk, "label" ):
            if chunk.label() == "GPE" or chunk.label() == "GSP":
                locations.append( chunk )
    return locations

def get_emails( text ):
    return email_re.findall( text )

def get_oibs( text ):
    return oib_re.findall( text )

def get_jmbgs( text ):
    return jmbg_re.findall( text )

def get_ips( text ):
    return ip_re.findall( text )

def get_tels( text ):
    nums = tel_re.findall( text )
    nums = [ ''.join( i ) for i in nums ]
    return nums

def get_macs( text ):
    return mac_re.findall( text )

def get_gps( text ):
    return gps_re.findall( text )

def get_cards( text ):
    return card_re.findall( text )

def parse_mdb( fl ):
    tables = mdb_tables( fl )
    data = ' '.join( tables ) + ' '
    for table in tables:
        rows = mdb_table_data( fl, table )
        data = data + ' '.join( [ ' '.join( r ) for r in rows ] )
    return data

def mdb_tables( fl ):
    DELIMETER = '||||'
    if SYSTEM == 'Windows':
        print 'Parsing old Access files on Windows is not supported yet!'
        return ''
    elif SYSTEM == 'Linux' or SYSTEM == 'SunOS':
        print "Loading mdb-tools"
        tables = subprocess.check_output( [ 'mdb-tables', '-d"%s"' % DELIMETER, fl ] )
        tables = [ t.replace( '"', '' ) for t in tables.split( DELIMETER )[ :-1 ] ]
        return tables
    elif SYSTEM == 'Darwin':
        print 'Parsing old Access files Mac is not supported yet!'

class crazy_list( list ):
    def keys( self ):
        return self[ 0 ]
        
def mdb_table_data( fl, table ):
    DELIMETER = '||||'
    if SYSTEM == 'Windows':
        print 'Parsing old Access files on Windows is not supported yet!'
        return ''
    elif SYSTEM == 'Linux' or SYSTEM == 'SunOS':
        print "Loading mdb-tools"
        output = subprocess.check_output( [ 'mdb-export', '-d"%s"' % DELIMETER, fl, table ] )
        data = output.split( '\n' )
        
        rows = [ r.replace( '"', '' ).split( DELIMETER ) for r in data ]
        
        return crazy_list( rows )
    elif SYSTEM == 'Darwin':
        print 'Parsing old Access files Mac is not supported yet!'


def open_file_with_default_app( filename ):
    if SYSTEM == 'Windows':
        try:
            retcode = subprocess.call( [ "start", filename ], shell=True )
            if retcode < 0:
                print >> sys.stderr, "Child was terminated by signal", -retcode
            else:
                print >> sys.stderr, "Child returned", retcode
        except OSError, e:
            print >> sys.stderr, "Execution failed:", e
    elif SYSTEM == 'Linux' or SYSTEM == 'SunOS':
        try:
            print filename
            env = os.environ
            env[ 'XDG_DATA_DIRS' ] = '/usr/share/ubuntu:/usr/local/share:/usr/share:/var/lib/snapd/desktop'
            envs = sorted( env.items(), key=lambda x: x[ 0 ] )
            for k, v in envs:
                print k, '==>', v
                if env[ 'GTK_DATA_PREFIX' ] in v:
                    print '+' * 50
            retcode = subprocess.Popen( [ "gio", "open", filename ], env=env, shell=True,
                                    stdout=file_obj, stderr=subprocess.STDOUT,
                                    stdin=subprocess.PIPE)
            retcode.wait()
            if retcode < 0:
                print >> sys.stderr, "Child was terminated by signal", -retcode
            else:
                print >> sys.stderr, "Child returned", retcode
                if retcode > 0:
                    try:
                        retcode = subprocess.call( [ "gedit", filename ], env=env )
                    except:
                        print  >> sys.stderr, 'Failed miserabely to open report file ...'
        except OSError, e:
            print >> sys.stderr, "Execution failed:", e
        except:
            try:
                retcode = subprocess.call( [ "xdg-open", filename ], shell=True )
                if retcode < 0:
                    print >> sys.stderr, "Child was terminated by signal", -retcode
                else:
                    print >> sys.stderr, "Child returned", retcode
            except OSError, e:
                print >> sys.stderr, "Execution failed:", e
    elif SYSTEM == 'Darwin':
        try:
            retcode = subprocess.call( [ "open", filename ], shell=True)
            if retcode < 0:
                print >> sys.stderr, "Child was terminated by signal", -retcode
            else:
                print >> sys.stderr, "Child returned", retcode
        except OSError, e:
            print >> sys.stderr, "Execution failed:", e
        
class Dataset:
    def __init__( self, kwargs ):
        self.filename = ''
        self.db = ''
        self.table = ''
        self.faces = False
        self.names = 0
        self.educations = 0
        self.sexes = 0
        self.locations = 0
        self.emails = 0
        self.oibs = 0
        self.jmbgs = 0
        self.ips = 0
        self.tels = 0
        self.keywords = 0
        self.macs = 0
        self.gps = 0
        self.cards = 0
        self.to_big = False
        self.vbox = False
        if kwargs.has_key( 'filename' ):
            self.filename = kwargs[ 'filename' ]
            self.subject = _( 'file' )
        if kwargs.has_key( 'db' ):
            self.db = kwargs[ 'db' ]
        if kwargs.has_key( 'table' ):
            self.table = kwargs[ 'table' ]
            self.subject = _( 'table' )
        if kwargs.has_key( 'faces' ):
            self.faces = kwargs[ 'faces' ]
        if kwargs.has_key( 'names' ):
            self.names = len( kwargs[ 'names' ] )
        if kwargs.has_key( 'locations' ):
            self.locations = len( kwargs[ 'locations' ] )
        if kwargs.has_key( 'emails' ):
            self.emails = len( kwargs[ 'emails' ] )
        if kwargs.has_key( 'oibs' ):
            self.oibs = len( kwargs[ 'oibs' ] )
        if kwargs.has_key( 'jmbgs' ):
            self.jmbgs = len( kwargs[ 'jmbgs' ] )
        if kwargs.has_key( 'ips' ):
            self.ips = len( kwargs[ 'ips' ] )
        if kwargs.has_key( 'tels' ):
            self.tels = len( kwargs[ 'tels' ] )
        if kwargs.has_key( 'macs' ):
            self.macs = len( kwargs[ 'macs' ] )
        if kwargs.has_key( 'gps' ):
            self.gps = len( kwargs[ 'gps' ] )
        if kwargs.has_key( 'cards' ):
            self.cards = len( kwargs[ 'cards' ] )
        if kwargs.has_key( 'keywords' ):
            self.keywords = len( kwargs[ 'keywords' ] )
        if kwargs.has_key( 'educations' ):
            self.educations = len( kwargs[ 'educations' ] )
        if kwargs.has_key( 'sexes' ):
            self.sexes = len( kwargs[ 'sexes' ] )
        if kwargs.has_key( 'to_big' ):
            self.to_big = kwargs[ 'to_big' ]
        if kwargs.has_key( 'vbox' ):
            self.vbox = kwargs[ 'vbox' ]

        self.r_faces = _( "The %s possibly contains human faces!" % self.subject )
        self.r_names = _( "The %s possibly contains personal names!" % self.subject )
        self.r_locations = _( "The %s possibly contains addresses and locations!" % self.subject )
        self.r_emails = _( "The %s possibly contains e-mail addresses!" % self.subject )
        self.r_oibs = _( "The %s possibly contains croatian personal identification numbers (OIB)!" % self.subject )
        self.r_jmbgs = _( "The %s possibly contains croatian personal identification numbers (JMBG)!" % self.subject )
        self.r_ips = _( "The %s possibly contains IP (Internet Protocol) addresses!" % self.subject )
        self.r_tels = _( "The %s possibly contains telephone numbers!" % self.subject )
        self.r_keywords = _( "The %s possibly contains privacy related keywords!" % self.subject )
        self.r_educations = _( "The %s possibly contains education related keywords!" % self.subject )
        self.r_sexes = _( "The %s possibly contains sexual orientation related keywords!" % self.subject )
        self.r_mac = _( "The %s possibly contains MAC addresses!" % self.subject )
        self.r_gps = _( "The %s possibly contains GPS coordinates!" % self.subject )
        self.r_cards = _( "The %s possibly contains bank card numbers!" % self.subject )

        self.risk = ''
        self.reasons = []

    def score( self ):
        if self.vbox:
            risk = 'High'
            reasons = [ 'The file is a container (disk image, archive, virtual machine descriptor etc.). Please extract it and rerun or in case of a virtual machine, run the program inside the virtual machine.' ]
        elif self.to_big:
            risk = 'Medium'
            reasons = [ 'The file is to big to process, please review manually!' ]
        else:
            risk = 'No risk'
            reasons = []
            if self.faces:
                risk = 'High'
                reasons.append( self.r_faces )
            if self.emails > 0:
                risk = 'High'
                reasons.append( self.r_emails )
            if self.oibs > 0:
                risk = 'High'
                reasons.append( self.r_oibs )
            if self.jmbgs > 0:
                risk = 'High'
                reasons.append( self.r_jmbgs )
            if self.ips > 0:
                risk = 'High'
                reasons.append( self.r_ips )
            if self.tels > 0:
                risk = 'High'
                reasons.append( self.r_tels )
            if self.macs > 0:
                risk = 'High'
                reasons.append( self.r_macs )
            if self.cards > 0:
                risk = 'High'
                reasons.append( self.r_cards )
            if self.names > 0:
                reasons.append( self.r_names )
            if self.locations > 0:
                reasons.append( self.r_locations )
            if self.gps > 0:
                reasons.append( self.r_gps )
            if self.educations > 0:
                reasons.append( self.r_educations )
            if self.sexes > 0:
                reasons.append( self.r_sexes )
            if self.keywords > 0:
                reasons.append( self.r_keywords )

            if risk == 'No risk':
                if self.names > NAMES_TRESHOLD:
                    risk = 'Medium'
                elif self.locations > LOCATIONS_TRESHOLD:
                    risk = 'Medium'
                elif self.gps > LOCATIONS_TRESHOLD:
                    risk = 'Medium'
                elif self.keywords > KEYWORDS_TRESHOLD:
                    risk = 'Medium'
                elif self.educations > KEYWORDS_TRESHOLD:
                    risk = 'Medium'
                elif self.sexes > KEYWORDS_TRESHOLD:
                    risk = 'Medium'
                elif self.names > 0:
                    risk = 'Low'
                elif self.locations > 0:
                    risk = 'Low'
                elif self.gps > 0:
                    risk = 'Low'
                elif self.keywords > 0:
                    risk = 'Low'
                elif self.educations > 0:
                    risk = 'Low'
                elif self.sexes > 0:
                    risk = 'Low'
                    
        self.risk = risk
        self.reasons = reasons
                
        return self.risk, self.reasons

    def to_json( self ):
        self.score()
        if self.filename:
            json = dumps( ( b64encode( self.filename ), self.risk, self.reasons ) )
        elif self.db and self.table:
            try:
                self.table = str( self.table )
            except:
                self.table = self.table.encode( 'utf-8' )
            #print self.db, b64encode( self.table ), self.risk, self.reasons
            json = dumps( ( self.db, b64encode( self.table ), self.risk, self.reasons ) )
        else:
            raise ValueError, 'The dataset has no subject!'
        return json
        

class GDPRAgent( Agent ):
    def say( self, msg ):
        print '%s: %s' % ( self.name.split( '@' )[ 0 ], repr( msg ) )

    def send_msg( self, receiver, message, ontology ):
        receiver = aid( name=receiver, addresses=[ "xmpp://%s" % receiver ] )
        msg = ACLMessage()
        msg.setPerformative( "inform" )
        msg.setOntology( ontology )
        msg.addReceiver( receiver )
        msg.setContent( b64encode( message ) )
        self.send( msg )

    def setmeup( self ):
        template = ACLTemplate()
        template.setOntology( 'stop' )
        t = MessageTemplate( template )
        
        self.addBehaviour( self.stop(), t )

    class stop( EventBehaviour ):
        def _process( self ):
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                self.myAgent.say( 'Stopping on request!' )
                self.myAgent._kill()
                
class GDPRParser( GDPRAgent ):
    def chunks( self, l, n ):
        """Yield successive n-sized chunks from l."""
        for i in range( 0, len( l ), n ):
            yield l[ i:i + n ]
    
    def extract( self, text, face=False ):
        if len( text ) > MAX_FILE_LEN:
            return { 'to_big':True }
        
        while self.flag:
            sleep( 0.1 )
        try:
            text = unicode( text, errors='ignore' )
        except:
            pass

        self.flag = True
        keywords = []
        educations = []
        sexes = []
        names = []
        locations = []
        emails = []
        oibs = []
        jmbgs = []
        ips = []
        tels = []
        macs = []
        gps = []
        cards = []
        for txt in self.chunks( text, MAX_TEXT_LEN ):
            
        
            low = txt.lower()
            
            for word in KEYWORDS:
                if word in low:
                    keywords.append( word )

            for word in EDUCATION_KEYWORDS:
                if word in low:
                    educations.append( word )

            for word in SEXUAL_ORIENTATION_KEYWORDS:
                if word in low:
                    sexes.append( word )

        
            try:
                names.extend( get_human_names( txt ) )
            except:
                try:
                    names.extend( get_human_names( txt.encode( 'utf-8' ) ) )
                except:
                    names.extend( get_human_names( repr( txt ) ) )
            try:
                locations.extend( get_locations( txt ) )
            except:
                try:
                    locations.extend( get_locations( txt.encode( 'utf-8' ) ) )
                except:
                    locations.extend( get_locations( repr( txt ) ) )
            emails.extend( get_emails( txt ) )
            oibs.extend( get_oibs( txt ) )
            jmbgs.extend( get_jmbgs( txt ) )
            ips.extend( get_ips( txt ) )
            tels.extend( get_tels( txt ) )
            macs.extend( get_macs( txt ) )
            gps.extend( get_gps( txt ) )
            cards.extend( get_cards( txt ) )
        self.flag = False
        result = {}
        result[ 'faces' ] = face
        result[ 'names' ] = names
        result[ 'educations' ] = educations
        result[ 'sexes' ] = sexes
        result[ 'locations' ] = locations
        result[ 'emails' ] = emails
        result[ 'oibs' ] = oibs
        result[ 'jmbgs' ] = jmbgs
        result[ 'ips' ] = ips
        result[ 'tels' ] = tels
        result[ 'keywords' ] = keywords
        result[ 'macs' ] = macs
        result[ 'gps' ] = gps
        result[ 'cards' ] = cards
        return result

    
    def file_parse( self, fl, mime=None ):
        self.say( 'Parsing file: %s' % fl )
        try:
            fsize = os.stat( fl ).st_size
        except Exception as e:
            fsize = os.stat( fl.decode( 'utf-8' ) ).st_size
                
        if fsize > MAX_FILE_LEN:
            fdesc = Dataset( { 'to_big':True, 'filename':fl } )
        else:
            #print '?'*100, fl
            fln, ext = os.path.splitext( fl )
            face = False
            try:
                Image.open( fl )
                if recognize( fl ):
                    face = True
            except:
                self.say( 'File %s is not an image, just continuing ...' % fl )
            if ext != '.mdb':
                try:
                    try:
                        txt = extract( fl )
                    except Exception as e1:
                        print 'error1'*50, e1
                        try:
                            txt = extract( fl.decode( 'utf-8' ) )
                        except Exception as e2:
                            print 'error2'*50, e2
                            try:
                                txt = extract( fl.decode( 'cp1252' ) )
                            except Exception as e3:
                                print 'error3'*50, e3
                                try:
                                    txt = extract( fl.decode( sys.getdefaultencoding() ) )
                                except Exception as e4:
                                    print 'error4'*50, e4
                                    txt = extract( fl.decode( 'utf-8' ).encode( sys.getdefaultencoding() ) )
                                
                except Exception as e:
                    if mime:
                        ext = MIMES2TYPES[ mime ]
                        txt = extract( fl, ext=ext )
                    else:
                        print 'error5'*50, e
                        raise e
            else:
                txt = parse_mdb( fl )
        
            results = self.extract( txt, face )
        
            results[ 'filename' ] = fl
            fdesc = Dataset( results )
        risk, reasons = fdesc.score()
        if risk != 'No risk':
            agg = get_aggregator()
            content = fdesc.to_json()
            self.send_msg( agg, content, 'file' )
        else:
            self.send_msg( get_file_searcher(), fl, 'confirm_parsing' )

    def table_parse( self, db, table, columns, data ):
        self.say( 'Parsing table: %s' % table )
        txt = table + ' ' + ' '.join( columns ) + ' ' + data
        result = self.extract( txt )
        result[ 'table' ] = table + '( ' + ' '.join( columns ) + ' )'
        result[ 'db' ] = db
        tdesc = Dataset( result )
        risk, reasons = tdesc.score()
        if risk != 'No risk':
            agg = get_aggregator()
            content = tdesc.to_json()
            self.send_msg( agg, content, 'table' )
        else:
            self.send_msg( get_db_searcher(), dumps( ( db, table ) ), 'confirm_parsing' )
        
    class parse_file( EventBehaviour ):
        def _process( self ):
            global ERRORS
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                try:
                    fl = b64decode( self.msg.getContent() )
                except Exception as e:
                    print 'E1', e
                try:
                    fl, mime = loads( fl )
                except Exception as e:
                    print 'E2', e
                try:
                    fl = b64decode( fl )
                except Exception as e:
                    print 'E3', e
                try:
                    self.myAgent.say( 'Got a file to parse: %s' % fl )
                except Exception as e:
                    print 'E4', e
                try:
                    self.myAgent.file_parse( fl, mime )
                except Exception as e:
                    ERRORS.append( ( fl, e ) )
                    print '\nERROR: 1, Error while parsing file', fl, e
                    self.myAgent.send_msg( get_file_searcher(), fl, 'confirm_parsing' )
                    
    class parse_vbox( EventBehaviour ):
        def _process( self ):
            global ERRORS
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                try:
                    fl = b64decode( self.msg.getContent() )
                except Exception as e:
                    print 'E1', e
                try:
                    fl, mime = loads( fl )
                except Exception as e:
                    print 'E2', e
                try:
                    fl = b64decode( fl )
                except Exception as e:
                    print 'E3', e
                try:
                    self.myAgent.say( 'Got a file to parse: %s' % fl )
                except Exception as e:
                    print 'E4', e
                try:
                    # TODO: ADD High risk!
                    fdesc = Dataset( { 'vbox':True, 'filename':fl } )
                    risk, reasons = fdesc.score()
                    agg = get_aggregator()
                    content = fdesc.to_json()
                    self.myAgent.send_msg( agg, content, 'file' )
                except Exception as e:
                    ERRORS.append( ( fl, e ) )
                    print '\nERROR: 1, Error while parsing file', fl, e
                    self.myAgent.send_msg( get_file_searcher(), fl, 'confirm_parsing' )

    class parse_table( EventBehaviour ):
        def _process( self ):
            global ERRORS
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                try:
                    dd = b64decode( self.msg.getContent() )
                    db, table, columns, data = loads( dd )
                    self.myAgent.say( 'Got a database table to parse: "%s"' % table )
                    self.myAgent.table_parse( db, table, columns, data )
                except Exception as e:
                    ERRORS.append( ( db, table, e ) )
                    print '\nERROR: 2, Error while parsing table', db, table, e
                    self.myAgent.send_msg( get_db_searcher(), dumps( ( db, table ) ), 'confirm_parsing' )

    def _setup( self ):
        self.setmeup()

        # Flag if a larger text is being processed
        # to wait until it is finished
        self.flag = False
        
        template = ACLTemplate()
        template.setOntology( 'parse file' )
        t = MessageTemplate( template )
        
        self.addBehaviour( self.parse_file(), t )
        
        template = ACLTemplate()
        template.setOntology( 'parse table' )
        t = MessageTemplate( template )
        
        self.addBehaviour( self.parse_table(), t )
        
        template = ACLTemplate()
        template.setOntology( 'parse vbox' )
        t = MessageTemplate( template )
        
        self.addBehaviour( self.parse_vbox(), t )


class GDPRAggregator( GDPRAgent ):
    class aggregate_file( EventBehaviour ):
        def _process( self ):
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                content = self.msg.getContent()
                decoded = b64decode( content )
                json = loads( decoded )
                filename, risk, reasons = json
                filename = b64decode( filename )
                self.myAgent.say( 'Got file to aggregate "%s" with risk "%s"' % ( repr( filename ), risk ) )
                t = transaction.get()
                self.myAgent.db[ 'files' ][ filename ] = PersistentMapping()
                self.myAgent.db[ 'files' ][ filename ][ 'risk' ] = risk
                self.myAgent.db[ 'files' ][ filename ][ 'reasons' ] = reasons
                t.commit()

                self.myAgent.say( 'Stored file "%s"' % filename )
                self.myAgent.send_msg( get_file_searcher(), filename, 'confirm_parsing' )

    class aggregate_table( EventBehaviour ):
        def _process( self ):
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                content = self.msg.getContent()
                decoded = b64decode( content )
                json = loads( decoded )
                db, table, risk, reasons = json
                table = b64decode( table )
                self.myAgent.say( 'Got table to aggregate "%s" with risk "%s"' % ( repr( table ), risk ) )
                t = transaction.get()
                if not self.myAgent.db[ 'databases' ].has_key( db ):
                    self.myAgent.db[ 'databases' ][ db ] = PersistentMapping()
                self.myAgent.db[ 'databases' ][ db ][ table ] = PersistentMapping()
                self.myAgent.db[ 'databases' ][ db ][ table ][ 'risk' ] = risk
                self.myAgent.db[ 'databases' ][ db ][ table ][ 'reasons' ] = reasons
                t.commit()

                self.myAgent.say( 'Stored table "%s"' % table )
                self.myAgent.send_msg( get_db_searcher(), dumps( ( db, table.split( '(' )[ 0 ] ) ), 'confirm_parsing' )

    class report( EventBehaviour ):
        def _process( self ):
            global DONE
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                name = self.msg.getSender().getName()
                if name == get_file_searcher():
                    self.myAgent.file_searcher_report = True
                elif name == get_db_searcher():
                    self.myAgent.db_searcher_report = True
                if self.myAgent.file_searcher_report and self.myAgent.db_searcher_report:
                    hrl = [ ( i, j ) for i, j in self.myAgent.db[ 'files' ].items() if j[ 'risk' ] == 'High' ]
                    mrl = [ ( i, j ) for i, j in self.myAgent.db[ 'files' ].items() if j[ 'risk' ] == 'Medium' ]
                    lrl = [ ( i, j ) for i, j in self.myAgent.db[ 'files' ].items() if j[ 'risk' ] == 'Low' ]


                    print self.myAgent.db[ 'databases' ]
                    print ERRORS
                    high_risk_db = sum( [ len( [ j for j in i.values() if j[ 'risk' ] == 'High' ] ) for i in self.myAgent.db[ 'databases' ].values() ] )
                    medium_risk_db = sum( [ len( [ j for j in i.values() if j[ 'risk' ] == 'Medium' ] ) for i in self.myAgent.db[ 'databases' ].values() ] )
                    low_risk_db = sum( [ len( [ j for j in i.values() if j[ 'risk' ] == 'Low' ] ) for i in self.myAgent.db[ 'databases' ].values() ] )
                    
                    high_risk = len( hrl )
                    medium_risk = len( mrl )
                    low_risk = len( lrl )
                    r = 'R E P O R T '
                    l = 200
                    sp = ( l - len( r ) ) / 2 - 1 
                    print '+' * l
                    print '|' + ' ' * sp + r + ' ' * sp + '|'
                    print '+' * l
                    print
                    print 'Time used for analysis:', str( datetime.now() - START )
                    print
                    print 'Found %d high risk files!' % high_risk
                    print 'Found %d medium risk files!' % medium_risk
                    print 'Found %d low risk files!' % low_risk
                    if __EDITION__ == 'FREE':
                        DONE = True
                        return
                    print
                    print 'Found %d high risk tables!' % high_risk_db
                    print 'Found %d medium risk tables!' % medium_risk_db
                    print 'Found %d low risk tables!' % low_risk_db
                    
                    if hrl:
                        print '+' * l
                        print 'High risk files:'
                        for f, v in hrl:
                            print
                            print f
                            for reason in v[ 'reasons' ]:
                                print '\t', reason

                    if mrl:
                        print '+' * l
                        print 'Medium risk files:'
                        for f, v in mrl:
                            print
                            print f
                            for reason in v[ 'reasons' ]:
                                print '\t', reason
                                
                                
                    if lrl:
                        print '+' * l
                        print 'Low risk files:'
                        for f, v in lrl:
                            print
                            print f
                            for reason in v[ 'reasons' ]:
                                print '\t', reason

                    print '+' * l

                    first = True
                    for name, db in self.myAgent.db[ 'databases' ].items():
                        if db:
                            if first:
                                r = 'D A T A B A S E S'
                                sp = ( l - len( r ) ) / 2 
                                print '|' + ' ' * sp + r + ' ' * sp + '|'
                                print '+' * l
                                first = False
                            
                            sp = ( l - len( name ) ) / 2 - 1 
                            print '|' + ' ' * sp + name + ' ' * sp + '|'

                            hrdb = [ ( i, j ) for i, j in db.items() if j[ 'risk' ] == 'High' ]
                            if hrdb:
                                print '+' * l
                                print 'High risk tables:'
                                for f, v in hrdb:
                                    print
                                    print f
                                    for reason in v[ 'reasons' ]:
                                        print '\t', reason

                            mrdb = [ ( i, j ) for i, j in db.items() if j[ 'risk' ] == 'Medium' ]
                            if mrdb:
                                print '+' * l
                                print 'Medium risk tables:'
                                for f, v in mrdb:
                                    print
                                    print f
                                    for reason in v[ 'reasons' ]:
                                        print '\t', reason

                            lrdb = [ ( i, j ) for i, j in db.items() if j[ 'risk' ] == 'Low' ]
                            if lrdb:
                                print '+' * l
                                print 'Low risk tables:'
                                for f, v in lrdb:
                                    print
                                    print f
                                    for reason in v[ 'reasons' ]:
                                        print '\t', reason
                            print '+' * l
                    #DONE = True

    class report_to_file( EventBehaviour ):
        def _process( self ):
            global DONE, REPORT_FILE, DBFILE, DBFOLDER
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                name = self.msg.getSender().getName()
                if name == get_file_searcher():
                    self.myAgent.file_searcher_report = True
                    print 'FileSearcher complete!'
                elif name == get_db_searcher():
                    self.myAgent.db_searcher_report = True
                    print 'DBSearcher complete!'
                if self.myAgent.file_searcher_report and self.myAgent.db_searcher_report:
                    unique, username = get_cpu_id()
                    
                    REPORT_FILE = os.path.join( 'data', 'report_' + unique + '_' + username + '_' + str( datetime.now() ).split( '.' )[ 0 ].replace( ' ', '_' ).replace( ':', '-' ) + '.txt' )
                    
                    fh = open( REPORT_FILE, 'w' )
                    hrl = [ ( i, j ) for i, j in self.myAgent.db[ 'files' ].items() if j[ 'risk' ] == 'High' ]
                    mrl = [ ( i, j ) for i, j in self.myAgent.db[ 'files' ].items() if j[ 'risk' ] == 'Medium' ]
                    lrl = [ ( i, j ) for i, j in self.myAgent.db[ 'files' ].items() if j[ 'risk' ] == 'Low' ]
                    
                    #print self.myAgent.db[ 'databases' ]
                    #print ERRORS
                    high_risk_db = sum( [ len( [ j for j in i.values() if j[ 'risk' ] == 'High' ] ) for i in self.myAgent.db[ 'databases' ].values() ] )
                    medium_risk_db = sum( [ len( [ j for j in i.values() if j[ 'risk' ] == 'Medium' ] ) for i in self.myAgent.db[ 'databases' ].values() ] )
                    low_risk_db = sum( [ len( [ j for j in i.values() if j[ 'risk' ] == 'Low' ] ) for i in self.myAgent.db[ 'databases' ].values() ] )
                    high_risk = len( hrl )
                    medium_risk = len( mrl )
                    low_risk = len( lrl )
                    r = 'R E P O R T '
                    l = 200
                    sp = ( l - len( r ) ) / 2 - 1 
                    print >> fh, '+' * l
                    print >> fh, '|' + ' ' * sp + r + ' ' * sp + '|'
                    print >> fh, '+' * l
                    print >> fh, '' 
                    print >> fh, 'Time used for analysis:', str( datetime.now() - START )
                    print >> fh, ''
                    print >> fh, 'Found %d high risk files!' % high_risk
                    print >> fh, 'Found %d medium risk files!' % medium_risk
                    print >> fh, 'Found %d low risk files!' % low_risk
                    print >> fh, ''
                    if __EDITION__ == 'FREE':
                        DONE = True
                        fh.close()
                        try:
                            for fl in glob( DBFILE + '*' ):
                                os.remove( fl )
                                print 'Removed:', fl
                        except Exception as e:
                            print e
                        self.myAgent.init_db()
                        return
                    print >> fh, 'Found %d high risk tables!' % high_risk_db
                    print >> fh, 'Found %d medium risk tables!' % medium_risk_db
                    print >> fh, 'Found %d low risk tables!' % low_risk_db
                    if hrl:
                        print >> fh, '+' * l
                        print >> fh, 'High risk files:'
                        for f, v in hrl:
                            print >> fh, ''
                            print >> fh, f
                            for reason in v[ 'reasons' ]:
                                print >> fh, '\t', reason
                    if mrl:
                        print >> fh, '+' * l
                        print >> fh, 'Medium risk files:'
                        for f, v in mrl:
                            print >> fh, ''
                            print >> fh, f
                            for reason in v[ 'reasons' ]:
                                print >> fh, '\t', reason
                                
                    if lrl:
                        print >> fh, '+' * l
                        print >> fh, 'Low risk files:'
                        for f, v in lrl:
                            print >> fh, ''
                            print >> fh, f
                            for reason in v[ 'reasons' ]:
                                print >> fh, '\t', reason

                    print >> fh, '+' * l

                    first = True
                    for name, db in self.myAgent.db[ 'databases' ].items():
                        if db:
                            if first:
                                r = 'D A T A B A S E S'
                                sp = ( l - len( r ) ) / 2 
                                print >> fh, '|' + ' ' * sp + r + ' ' * sp + '|'
                                print >> fh, '+' * l
                                first = False
                            
                            sp = ( l - len( name ) ) / 2 - 1 
                            print >> fh, '|' + ' ' * sp + name + ' ' * sp + '|'

                            hrdb = [ ( i, j ) for i, j in db.items() if j[ 'risk' ] == 'High' ]
                            if hrdb:
                                print >> fh, '+' * l
                                print >> fh, 'High risk tables:'
                                for f, v in hrdb:
                                    print >> fh, ''
                                    print >> fh, f
                                    for reason in v[ 'reasons' ]:
                                        print >> fh, '\t', reason

                            mrdb = [ ( i, j ) for i, j in db.items() if j[ 'risk' ] == 'Medium' ]
                            if mrdb:
                                print >> fh, '+' * l
                                print >> fh, 'Medium risk tables:'
                                for f, v in mrdb:
                                    print >> fh, ''
                                    print >> fh, f
                                    for reason in v[ 'reasons' ]:
                                        print >> fh, '\t', reason

                            lrdb = [ ( i, j ) for i, j in db.items() if j[ 'risk' ] == 'Low' ]
                            if lrdb:
                                print >> fh, '+' * l
                                print >> fh, 'Low risk tables:'
                                for f, v in lrdb:
                                    print >> fh, ''
                                    print >> fh, f
                                    for reason in v[ 'reasons' ]:
                                        print >> fh, '\t', reason
                            print >> fh, '+' * l
                            
                    fh.close()
                    try:
                        for fl in glob( DBFILE + '*' ):
                            os.remove( fl )
                            print 'Removed:', fl
                    except Exception as e:
                        print e
                    self.myAgent.init_db()
                    
                    print 'Wrote report to', REPORT_FILE
                    DONE = True

                    
    def init_db( self ):
        global DBFOLDER, DBFILE
        DBFOLDER = tempfile.mkdtemp()
        DBFILE = os.path.join( DBFOLDER, 'pa.fs' )
        self.storage, self.zdb, self.conn = open_fs( DBFILE )
        self.db = self.conn.root()

        if not self.db.has_key( 'files' ):
            t = transaction.get()
            self.db[ 'files' ] = PersistentMapping()
            self.db[ 'databases' ] = PersistentMapping()
            self.db[ 'emails' ] = PersistentMapping()
            t.commit()
                
    def _setup( self ):
        self.setmeup()
        self.init_db()
        self.file_searcher_report = False
        self.db_searcher_report = False
        
        template = ACLTemplate()
        template.setOntology( 'report' )
        t = MessageTemplate( template )
        
        #self.addBehaviour( self.report(), t )
        self.addBehaviour( self.report_to_file(), t )

        

        template = ACLTemplate()
        template.setOntology( 'file' )
        t = MessageTemplate( template )
        
        self.addBehaviour( self.aggregate_file(), t )
        
        template = ACLTemplate()
        template.setOntology( 'table' )
        t = MessageTemplate( template )
        
        self.addBehaviour( self.aggregate_table(), t )
        
class FileSearcher( GDPRAgent ):
    class search_files( OneShotBehaviour ):
        def _process( self ):
            global NUM_FILES
            self.myAgent.say( 'Searching files ...' )
            if SYSTEM == 'Windows':
                self.myAgent.say( "I'm on Windows, now what?" )
                root_dir = WINDOWS_ROOT
            elif SYSTEM == 'Linux' or SYSTEM == 'SunOS':
                self.myAgent.say( "I'm on Linux, yay!" )
                root_dir = LINUX_ROOT
            elif SYSTEM == 'Darwin':
                self.myAgent.say( 'Mac is not supported yet!' )
                self.myAgent._kill()

            self.myAgent.say( 'Root dir is "%s"' % root_dir )
            self.myAgent.say( 'Estimating number of files to analyze ...' )
            if HASMAX:
                NUM_FILES = MAXFILES
            else:
                NUM_FILES = sum( [ len( files ) for root, dirs, files in os.walk( root_dir ) ] )
            self.myAgent.say( 'Got %d files to analyze!' % NUM_FILES )

            stop = MAXFILES
            brojac = 0
            for root, dirs, files in os.walk( root_dir ):
                brojac += 1
                #print "XXXXXX", brojac
                #print root
                #print dirs
                #print files
                self.myAgent.say( ( root, dirs, files ) )
                for f in files:
                    #print brojac, 1
                    fln, ext = os.path.splitext( f )
                    #print brojac, 2
                    ext = ext[ 1: ]
                    #print brojac, 3
                    fl = os.path.join( root, f )
                    #print brojac, 4
                    try:
                        mime = get_mime( fl )
                    except: # ONLY FOR VBOXES
                        mime = ext
                    #print brojac, 5, mime
                    is_image = True
                    try:
                        Image.open( fl )
                    except:
                        is_image = False
                    if ext in FILETYPES or mime in MIMETYPES or ext in VBOXES or is_image:
                        #print brojac, 6
                        #print ext
                        #print mime
                        self.myAgent.say( 'Found file of type ' + ( ext or mime ) + ': ' + fl )
                        #print brojac, 7
                        parser = get_parser( ext )
                        #print brojac, 8
                        if parser:
                            #print brojac, 9
                            #print fl
                            #print mime
                            try: 
                                data = dumps( ( b64encode( fl ), mime ) )
                            except Exception as e:
                                fl = fl.encode( 'utf-8' )
                                data = dumps( ( b64encode( fl ), mime ) )
                            #print brojac, 10
                            
                            if ext in VBOXES:
                                self.myAgent.send_msg( parser, data, 'parse vbox' )
                            else:
                                self.myAgent.send_msg( parser, data, 'parse file' )
                            #print brojac, 11
                            self.myAgent.files.append( fl )
                            #print brojac, 12
                            counter = 0
                            #print brojac, 13
                            while len( self.myAgent.files ) > MAXLEN:
                                #print brojac, 14
                                sleep( 0.1 )
                                #print brojac, 15
                                if fl in [ e[ 0 ] for e in ERRORS ]:
                                    #print brojac, 16
                                    self.myAgent.files.remove( fl )
                                #print brojac, 17
                                counter += 1
                                #print brojac, 18
                                if counter > 100:
                                    #print counter
                                    MEMORY = psutil.virtual_memory()
                                    #print MEMORY
                                    if MEMORY.percent > 90:
                                        self.myAgent.say( 'Less then 10 % memory available, going to sleep a bit until other files process.' )
                                        sleep( 30 )
                                        counter = 0
                        if HASMAX:
                            print 'STOP:', stop
                            stop -= 1
                            if stop <= 0:
                                break
                if stop <= 0:
                    break
           
            #print brojac, 19
            self.myAgent.say( 'Done!' )
            self.myAgent.done_searching = True
            

    class confirm_parsing( EventBehaviour ):
        def _process( self ):
            global PARSED
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                fl = b64decode( self.msg.getContent() )
                try:
                    self.myAgent.files.remove( fl )
                except ValueError:
                    pass
                PARSED += 1
                self.myAgent.say( 'Confirmed parsing file "%s"' % fl )
                if self.myAgent.files == [] and self.myAgent.done_searching:
                    self.myAgent.say( 'All files have been parsed!' )
                    self.myAgent.send_msg( get_aggregator(), 'Hello you, could you please write the report?', 'report' )
                    self.myAgent._kill()
                
                
    class print_status( PeriodicBehaviour ):
        def _onTick( self ):
            if self.myAgent.files:
                self.myAgent.say( 'Files left to confirm: ' + repr( self.myAgent.files ) )
                    
    def _setup( self ):
        self.setmeup()
        self.files = []
        self.done_searching = False
        
        template = ACLTemplate()
        template.setOntology( 'confirm_parsing' )
        t = MessageTemplate( template )

        self.cp = self.confirm_parsing()
        self.addBehaviour( self.cp, t )

        self.ps = self.print_status( 10 )
        self.addBehaviour( self.ps )
        
        self.sf = self.search_files()
        self.addBehaviour( self.sf )

class DBSearcher( GDPRAgent ):
    class search_dbs( OneShotBehaviour ):
        def _process( self ):
            global NUM_DBS
            access = False
            odbc = False
            for conn_string in CONNSTRINGS:
                print conn_string
                try:
                    if 'oracle+cx_oracle' in conn_string:
                        engine = create_engine( conn_string )
                    else:
                        engine = create_engine( conn_string, encoding='utf8' )
                except:
                    if SYSTEM == 'Windows':
                        if 'Microsoft Access' in conn_string:
                            access = True
                            conn = pyodbc.connect( conn_string )
                            cursor = conn.cursor()
                            tables = [ row.table_name for row in cursor.tables( tableType='TABLE' ) ]
                        elif 'DSN=' in conn_string:
                            odbc = True
                            try:
                                conn = pyodbc.connect( conn_string )
                                cursor = conn.cursor()
                                tables = [ row.table_name for row in cursor.tables( tableType='TABLE' ) ]
                            except:
                                self.myAgent.say( 'Invalid connection string: "%s"' % conn_string )
                                continue
                        else:
                            self.myAgent.say( 'Invalid connection string: "%s"' % conn_string )
                            continue
                    else:
                        if  'Microsoft Access' in conn_string:
                            cs = conn_string.split( 'DBQ=' )
                            cs = cs[ 1 ].split( ';' )[ 0 ]
                            print cs
                            tables = mdb_tables( cs )
                            access = True
                        else: # TODO add ODBC for Linux
                            try:
                                conn = pyodbc.connect( conn_string )
                                cursor = conn.cursor()
                                tables = [ row.table_name for row in cursor.tables( tableType='TABLE' ) ]
                            except:
                                self.myAgent.say( 'Invalid connection string: "%s"' % conn_string )
                                continue
                if not access and not odbc:
                    if not 'oracle+cx_oracle' in conn_string:
                        tables = engine.table_names()
                        print tables
                    else:
                        try:
                            res = engine.execute( 'SELECT table_name FROM user_tables' )
                        except Exception as e:
                            print e
                            raise Exception, repr( e )
                        tables = [ r[ 0 ] for r in res ]
                print tables
                NUM_DBS += len( tables )
                for t in tables:
                    try:
                        self.myAgent.say( 'Fetching table "' + t + '"' )

                        if not access and not odbc:
                            try:
                                sql = u'SELECT * FROM "%s"' % t
                                result = engine.execute( sql )
                            except:
                                sql = u'SELECT * FROM %s' % t
                                result = engine.execute( sql )
                        else:
                            if SYSTEM == 'Windows':
                                try:
                                    cursor.execute( u'SELECT * FROM "%s"' % t )
                                    res = cursor.fetchall()
                                    columns = [ column[0] for column in cursor.description ]
                                    result = crazy_list( [] )
                                    result.append( columns )
                                    result.extend( res )
                                except:
                                    self.myAgent.say( 'Error while fetching table: "%s"' % t )
                                    continue
                            else: # TODO add ODBC for Linux
                                result = mdb_table_data( cs, t )    
                        def tostr( elem ):
                            try:
                                return str( elem )
                            except:
                                return str( elem.encode( 'utf-8' ) )
                        rows = [ ' '.join( [ tostr( elem or ' ' ) for elem in row ] ) for row in result ]
                        data = ' '.join( rows )
                        desc = dumps( ( conn_string, t, result.keys(), data ) )
                        self.myAgent.send_msg( get_parser(), desc, 'parse table' )
                        self.myAgent.tables.append( dumps( ( conn_string, t ) ) )
                        
                        while len( self.myAgent.tables ) > MAXLEN:
                            sleep( 0.1 )
                            if ( conn_string, t ) in [ ( e[ 0 ], e[ 1 ] ) for e in ERRORS ]:
                                self.myAgent.tables.remove( dumps( ( conn_string, t ) ) )
                            
                            
                    except Exception as e:
                        print '\nERROR: 3', e
            self.myAgent.done_searching = True
                
    
    class confirm_parsing( EventBehaviour ):
        def _process( self ):
            global PARSED
            self.msg = None
            self.msg = self._receive( True )
            if self.msg:
                t = b64decode( self.msg.getContent() )
                self.myAgent.tables.remove( t )
                self.myAgent.say( 'Confirmed parsing table "%s"' % t )
                PARSED += 1
                if self.myAgent.tables == [] and self.myAgent.done_searching:
                    self.myAgent.say( 'All tables have been parsed!' )
                    self.myAgent.send_msg( get_aggregator(), 'Hello you, could you please write the report?', 'report' )
                    self.myAgent._kill()
                
    class print_status( PeriodicBehaviour ):
        def _onTick( self ):
            if self.myAgent.tables:
                self.myAgent.say( 'Tables left to confirm: ' + repr( self.myAgent.tables ) )
                    
    def _setup( self ):
        self.setmeup()
        self.tables = []
        self.done_searching = False
        
        template = ACLTemplate()
        template.setOntology( 'confirm_parsing' )
        t = MessageTemplate( template )

        self.cp = self.confirm_parsing()
        self.addBehaviour( self.cp, t )

        self.ps = self.print_status( 10 )
        self.addBehaviour( self.ps )

        self.sd = self.search_dbs()
        self.addBehaviour( self.sd )

def get_parser( type=None ):
    #if type not in [ 'jpg', 'jpeg', 'png', 'tif', 'tiff', 'gif' ]:
    return 'parser_' + USERNAME + '@' + SERVER

def get_aggregator():
    return 'aggregator_' + USERNAME + '@' + SERVER

def get_file_searcher():
    return 'filesearcher_' + USERNAME + '@' + SERVER

def get_db_searcher():
    return 'dbsearcher_' + USERNAME + '@' + SERVER


import Tkinter as tk
import ttk
from PIL import ImageTk as itk
if SYSTEM == 'Windows' or 'CYGWIN' in SYSTEM:
    from PIL import Image
else:
    import Image
import tkMessageBox
import tkFileDialog

__VERSION__ = '1.0'
__EDITION__ = 'C5' # FREE, C5, C10, C20+
APPICON = 'resources/icon.png'
APPBANNER = 'resources/banner.png'
IMGDB = 'resources/icons/database_go.png'
IMGFOLDER = 'resources/icons/folder_go.png'
IMGOPEN = 'resources/icons/folder_magnify.png'
IMGABOUT = 'resources/icons/help.png'
IMGREC = 'resources/icons/award_star_gold_2.png'
IMGYES = 'resources/icons/accept.png'
IMGNO = 'resources/icons/cancel.png'
IMGCONFIG = 'resources/icons/wrench.png'
class PriAnaGUI( tk.Tk ):
    def __init__( self, *args, **kwargs ):
        tk.Tk.__init__( self, *args, **kwargs )        
        self.tk.call( 'wm', 'title', self._w, 'Privacy Analysis %s %s' % ( __VERSION__, __EDITION__ ) )
        self.configure( background='#ffffff' )
        self.resizable( 0, 0 )
        self.imgicon = itk.PhotoImage( file=APPICON )
        self.imgFolder = itk.PhotoImage( file=IMGFOLDER )
        self.imgDB = itk.PhotoImage( file=IMGDB )
        self.imgAbout = itk.PhotoImage( file=IMGABOUT )
        self.imgRec = itk.PhotoImage( file=IMGREC )
        self.imgYes = itk.PhotoImage( file=IMGYES )
        self.imgNo = itk.PhotoImage( file=IMGNO )
        self.imgConfig = itk.PhotoImage( file=IMGCONFIG )
        self.tk.call( 'wm', 'iconphoto', self._w, self.imgicon )

        img = Image.open( APPBANNER )
        w, h = img.size
        #img = img.resize( ( w / 2, h / 2 ), Image.ANTIALIAS )
        self.phtLogo = itk.PhotoImage( img )
        self.lblLogo = tk.Label( self, image=self.phtLogo )
        self.lblLogo.pack()

        self.frmButtons = tk.Frame( self, background='#ffffff' )
        self.frmButtons.pack()
        
        #self.btnConfig = ttk.Button( self.frmButtons, text=_( "Configure" ), image=self.imgConfig, compound="left", command=self.config )
        #self.btnConfig.grid( row=0, column=0, padx=10 )

        self.btnFolders = ttk.Button( self.frmButtons, text=_( "Scan folder" ), image=self.imgFolder, compound="left", command=self.start )
        self.btnFolders.grid( row=0, column=1, padx=10 )
        
        self.btnDBS = ttk.Button( self.frmButtons, text=_( "Scan database" ), image=self.imgDB, compound="left", command=self.start_db )
        #if __EDITION__ != 'FREE' and NUM_CPUS > 1:
        self.btnDBS.grid( row=0, column=2, padx=10 )
        
        self.btnRec = ttk.Button( self.frmButtons, text=_( "Start recommendations" ), image=self.imgRec, compound="left", command=self.rec )
        #if __EDITION__ != 'FREE' and NUM_CPUS > 1:
        self.btnRec.grid( row=0, column=3, padx=10 )
        
        self.btnAbout = ttk.Button( self.frmButtons, text=_( "About" ), image=self.imgAbout, compound="left", command=self.about )
        #self.btnAbout.grid( row=0, column=3, padx=10 )
        
        
        self.style = ttk.Style( self )
        self.style.layout( 'text.Horizontal.TProgressbar', 
                     [ ( 'Horizontal.Progressbar.trough',
                         { 'children': [ ( 'Horizontal.Progressbar.pbar',
                                         { 'side': 'left', 'sticky': 'ns' } ) ],
                         'sticky': 'nswe' } ), 
                       ( 'Horizontal.Progressbar.label', { 'sticky': '' } ) ] )
        self.style.configure( 'text.Horizontal.TProgressbar', text='0.00 %' )
        # create progressbar
        self.variable = tk.DoubleVar( self )
        self.proMain = ttk.Progressbar( self, style='text.Horizontal.TProgressbar', variable=self.variable, length=w, mode="determinate" )
        self.proMain.pack()
        self.proMain[ "value" ] = 0.00

        self.protocol( "WM_DELETE_WINDOW", self.on_close )

    def about( self ):
        print 'about'

    def config( self ):
        self.config = PrianaConfig( self )
    
    def rec( self ):
        self.recommendations = PrianaRecommendations( self )
        
    def start( self ):
        global DONE, WINDOWS_ROOT, LINUX_ROOT, DARWIN_ROOT, TEST_FILES, TEST_DBS
        TEST_FILES = True
        TEST_DBS = False
        DONE = False
        root_dir = tkFileDialog.askdirectory( initialdir=expanduser( "~" ) )
        if root_dir:
            if SYSTEM == 'Windows':
                WINDOWS_ROOT = root_dir
            elif SYSTEM == 'Linux' or SYSTEM == 'SunOS':
                LINUX_ROOT = root_dir
            else:
                print 'Mac not supported yet!'
                sys.exit()
            test()
            self.btnFolders[ "text" ] = _( 'Scan started, plase wait!' )
            self.btnFolders[ "state" ] = 'disabled'
            self.btnDBS[ "state" ] = 'disabled'
            self.btnRec[ "state" ] = 'disabled'
            self.btnAbout[ "state" ] = 'disabled'
            self.update()
        
    def start_db( self ):
        global DONE
        DONE = False
        self.dbconfig = PrianaDBConfig( self )
        self.update()

    def update( self ):
        self.proMain[ "maximum" ] = NUM_FILES + NUM_DBS
        self.proMain[ "value" ] = PARSED
        self.variable.set( PARSED )
        progress = ( 100.0 * PARSED / ( NUM_FILES + NUM_DBS + 0.0000001 ) ) # to avoid ZeroDivisionError
        self.style.configure( 'text.Horizontal.TProgressbar', text='%.2f %%' % progress )
        if not DONE:
            self.after( 1000, self.update )
        else:
            self.style.configure( 'text.Horizontal.TProgressbar', text='%.2f %%' % 100.00 )
            self.on_finish( REPORT_FILE )

    def on_finish( self, report_file ):
        result = tkMessageBox.askquestion( _( "Analysis finished!" ), _( "The analysis has finished. Do you want to open the report?" ), icon='warning' )
        if result == 'yes':
            self.btnFolders[ "state" ] = 'enabled'
            self.btnDBS[ "state" ] = 'enabled'
            self.btnRec[ "state" ] = 'enabled'
            self.btnAbout[ "state" ] = 'enabled'
            self.btnFolders[ "text" ] = _( 'Scan folder' )
            rprt = ReportViewer( self, report_file )
        else:
            self.on_close()
        
            
    def on_close( self ):
        print 'Enough is enough...'
        try:
            os.remove( LOCKFILE )
        except:
            pass
        try:
            os.remove( 'roomdb.xml' )
        except:
            pass
        try:
            os.remove( 'user_db.xml' )
        except:
            pass
        try:
            os.remove( 'xmppd.xml' )
        except:
            pass
        try:
            os.remove( 'spade.xml' )
        except:
            pass
        pid = os.getpid()
        parent = psutil.Process( pid )
        for child in parent.children( recursive=True ):  
            child.kill()
        parent.kill()

class ReportViewer( tk.Toplevel ):

    def __init__( self, master, report_file, *args, **kwargs ):
        tk.Toplevel.__init__( self, master, *args, **kwargs )
        self.root = master
        if SYSTEM == 'Windows':
            self.state( 'zoomed' )
        else:
            w, h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            self.overrideredirect()
            self.geometry( "%dx%d+0+0" % ( w-20, h-20 ) )
        
        self.grab_set()
        self.tk.call( 'wm', 'iconphoto', self._w, master.imgicon )
        self.tk.call( 'wm', 'title', self._w, _( 'PriAna Report Viewer' ) )
        
        self.frmTxt = tk.Frame( self )
        self.frmTxt.pack( fill="both", expand=True )
        self.frmTxt.grid_propagate( False )
        
        self.frmTxt.grid_rowconfigure( 0, weight=1 )
        self.frmTxt.grid_columnconfigure( 0, weight=1 )

        self.txtReport = tk.Text( self.frmTxt, borderwidth=3, relief="sunken" )
        self.txtReport.config( font=( "Courier", 12 ), undo=True, wrap='none' )
        self.txtReport.grid( row=0, column=0, sticky="nsew", padx=2, pady=2 )

        self.scrReportY = tk.Scrollbar( self.frmTxt, command=self.txtReport.yview )
        self.scrReportY.grid( row=0, column=1, sticky='nsew' )
        self.txtReport[ 'yscrollcommand' ] = self.scrReportY.set
        
        self.scrReportX = tk.Scrollbar( self.frmTxt, command=self.txtReport.xview, orient='horizontal' )
        self.scrReportX.grid( row=1, column=0, sticky='news' )
        self.txtReport[ 'xscrollcommand' ] = self.scrReportX.set

        f = open( report_file )
        self.txtReport.insert( 0.0, f.read() )
        
        
class PrianaRecommendations( tk.Toplevel ):
    def __init__( self, master, *args, **kwargs ):
        tk.Toplevel.__init__( self, master, *args, **kwargs )
        self.master = master
        self.resizable( 0, 0 )
        self.geometry( "%dx%d+0+0" % ( 820, 520 ) )
        self.grab_set()
        self.tk.call( 'wm', 'iconphoto', self._w, master.imgicon )
        self.tk.call( 'wm', 'title', self._w, _( 'PriAna Expert System' ) )
        
        self.exp = rekodr()
        
        self.frmMain = tk.Frame( self, background='#ffffff' )
        self.frmMain.pack( fill="both", expand=True )

        self.frmTxt = tk.Frame( self.frmMain, background='#ffffff' ) 
        self.frmTxt.columnconfigure( 0, weight=1 )
        self.frmTxt.columnconfigure( 1, weight=1 )
        
        self.txtReport = tk.Text( self.frmTxt, borderwidth=0, relief="sunken" ) 
        self.txtReport.config( font=( "TkFixedFont", 12 ), undo=True, wrap='word' ) # 
        self.txtReport.grid( row=0, column=0, sticky="n", padx=2, pady=2 )

        self.scrReportY = tk.Scrollbar( self.frmTxt, command=self.txtReport.yview )
        self.scrReportY.grid( row=0, column=1, sticky='nsew' )
        self.txtReport[ 'yscrollcommand' ] = self.scrReportY.set

        self.frmTxt.pack( fill="both", expand=True )
        
        self.txtReport.delete( 1.0, 'end' )
        self.txtReport.insert( 0.0, self.exp.state )
        
        self.frmOKCancel = tk.Frame( self.frmMain, background='#ffffff' )
        self.btnDa = ttk.Button( self.frmOKCancel, text=_( "Da" ), image=self.master.imgYes, compound="left", command=self.da )
        self.btnDa.pack( side="right", pady=5, padx=5 )
        self.btnDa = ttk.Button( self.frmOKCancel, text=_( "Ne" ), image=self.master.imgNo, compound="left", command=self.ne )
        self.btnDa.pack( side="left", pady=5, padx=5 )
        self.frmOKCancel.pack( pady=5, padx=5 )
                
        self.frmOK = tk.Frame( self.frmMain, background='#ffffff' )
        self.btnDa = ttk.Button( self.frmOK, text=_( "OK" ), image=self.master.imgYes, compound="left", command=self.quit )
        self.btnDa.pack( pady=5, padx=5 )
        
    def send_answer( self, answer ):
        self.exp.interact( answer )
        self.txtReport.delete( 1.0, 'end' )
        self.txtReport.insert( 0.0, self.exp.state )
        if not '?' in self.exp.state:
            self.frmOKCancel.pack_forget()
            self.frmOK.pack( pady=5, padx=5 )
            
    def quit( self ):
        self.destroy()
    
    def da( self ):
        self.send_answer( 'da.' )
        
    def ne( self ):
        self.send_answer( 'ne.' )
        
        
class PrianaDBConfig( tk.Toplevel ):
    def __init__( self, master, *args, **kwargs ):
        tk.Toplevel.__init__( self, master, *args, **kwargs )
        self.master = master
        self.resizable( 0, 0 )
        self.grab_set()
        self.tk.call( 'wm', 'iconphoto', self._w, master.imgicon )
        self.tk.call( 'wm', 'title', self._w, _( 'Configure database connection' ) )
        
        
        self.PSQL_CON_STRING = 'postgresql+pg8000://%(user)s:%(password)s@%(host):%(port)s/%(dbname)s'
        self.MYSQL_CON_STRING = 'mysql+pymysql://%(user)s:%(password)s@%(host):%(port)s/%(dbname)s'
        
        self.SQLITE_CON_STRING = 'sqlite+pysqlite:///%(path)s'
        
        self.frmMain = tk.Frame( self, background='#ffffff' )
        self.frmMain.pack()        
        
        self.varDBType = tk.StringVar( self.master )
        self.varDBType.set( DBTYPES[ 0 ] )
        
        self.lblDBType = tk.Label( self.frmMain, background='#ffffff', text=_( 'Select a database type:' ) )
        self.lblDBType.grid( row=0, column=0 )
        self.optDBType = tk.OptionMenu( self.frmMain, self.varDBType, *DBTYPES, command=self.on_select )
        self.optDBType.grid( row=0, column=1 )
        
        # File type frame
        
        self.frmFileDB = tk.Frame( self.frmMain, background='#ffffff' )
        self.lblPath = tk.Label( self.frmFileDB, background='#ffffff', text=_( 'Path to database file:' ) )
        self.lblPath.grid( row=0, column=0, padx=5, pady=5, sticky=tk.E )
        
        self.frmSelectPath = tk.Frame( self.frmFileDB, background='#ffffff' )
        self.frmSelectPath.grid( row=0, column=1, padx=5, pady=5, sticky=tk.W )
        
        self.varPath = tk.StringVar( self.master )
        self.entPath = tk.Entry( self.frmSelectPath, textvariable=self.varPath )
        self.entPath.pack( side='left' )
        self.imgSelectPath = itk.PhotoImage( file=IMGOPEN )
        self.btnSelectPath = ttk.Button( self.frmSelectPath, image=self.imgSelectPath, command=self.open_file )
        self.btnSelectPath.pack( side='right' )
        
        self.lblFUsername = tk.Label( self.frmFileDB, background='#ffffff', text=_( 'Username (optional):' ) )
        self.lblFUsername.grid( row=1, column=0, padx=5, pady=5, sticky=tk.E )
        self.varUsername = tk.StringVar( self.master )
        self.entFUsername = tk.Entry( self.frmFileDB, textvariable=self.varUsername )
        self.entFUsername.grid( row=1, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        self.lblFPassword = tk.Label( self.frmFileDB, background='#ffffff', text=_( 'Password (optional):' ) )
        self.lblFPassword.grid( row=2, column=0, padx=5, pady=5, sticky=tk.E )
        self.varPassword = tk.StringVar( self.master )
        self.entFPassword = tk.Entry( self.frmFileDB, textvariable=self.varPassword, show="×" )
        self.entFPassword.grid( row=2, column=1, padx=5, pady=5, sticky=tk.W )
        
        self.frmFileDB.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
        
        # Server type frame
        
        self.frmServerDB = tk.Frame( self.frmMain, background='#ffffff' )
        self.lblHost = tk.Label( self.frmServerDB, background='#ffffff', text=_( 'Host and port:' ) )
        self.lblHost.grid( row=0, column=0, padx=5, pady=5, sticky=tk.E )
        
        self.frmHostPort = tk.Frame( self.frmServerDB, background='#ffffff' )
        self.frmHostPort.grid( row=0, column=1, padx=5, pady=5, sticky=tk.W )
        
        self.varHost = tk.StringVar( self.master )
        self.varHost.set( 'localhost' )
        self.entHost = tk.Entry( self.frmHostPort, textvariable=self.varHost, width=15 )
        self.entHost.pack( side='left' )
        
        self.varPort = tk.StringVar( self.master )
        self.entPort = tk.Entry( self.frmHostPort, textvariable=self.varPort, width=4 )
        self.entPort.pack( side='right' )
        
        self.lblSUsername = tk.Label( self.frmServerDB, background='#ffffff', text=_( 'Username:' ) )
        self.lblSUsername.grid( row=1, column=0, padx=5, pady=5, sticky=tk.E )
        #self.varUsername = tk.StringVar( self.master )
        self.entSUsername = tk.Entry( self.frmServerDB, textvariable=self.varUsername )
        self.entSUsername.grid( row=1, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        self.lblSPassword = tk.Label( self.frmServerDB, background='#ffffff', text=_( 'Password:' ) )
        self.lblSPassword.grid( row=2, column=0, padx=5, pady=5, sticky=tk.E )
        #self.varPassword = tk.StringVar( self.master )
        self.entSPassword = tk.Entry( self.frmServerDB, textvariable=self.varPassword, show="×" )
        self.entSPassword.grid( row=2, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        self.lblDBName = tk.Label( self.frmServerDB, background='#ffffff', text=_( 'Database name:' ) )
        self.lblDBName.grid( row=3, column=0, padx=5, pady=5, sticky=tk.E )
        self.varDBName = tk.StringVar( self.master )
        self.entDBName = tk.Entry( self.frmServerDB, textvariable=self.varDBName )
        self.entDBName.grid( row=3, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        #self.frmServerDB.grid( row=2, column=0, columnspan=2, padx=5, pady=5 )
        
        # ODBC type frame
        
        self.frmODBC = tk.Frame( self.frmMain, background='#ffffff' )
        
        DSNs = pyodbc.dataSources().keys()
        self.varDSN = tk.StringVar( self.master )
	try:
        	self.varDSN.set( DSNs[ 0 ] )
	except:
		srcs = _( 'No sources available!' )
        	self.varDSN.set( srcs )
		DSNs = [ srcs ]
        
        self.lblDSN = tk.Label( self.frmODBC, background='#ffffff', text=_( 'Data Source Name (DSN):' ) )
        self.lblDSN.grid( row=0, column=0 )
        self.optDSN = tk.OptionMenu( self.frmODBC, self.varDSN, *DSNs, command=self.on_select )
        self.optDSN.grid( row=0, column=1 )
        
        self.lblOUsername = tk.Label( self.frmODBC, background='#ffffff', text=_( 'Username (optional):' ) )
        self.lblOUsername.grid( row=1, column=0, padx=5, pady=5, sticky=tk.E )
        #self.varUsername = tk.StringVar( self.master )
        self.entOUsername = tk.Entry( self.frmODBC, textvariable=self.varUsername )
        self.entOUsername.grid( row=1, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        self.lblOPassword = tk.Label( self.frmODBC, background='#ffffff', text=_( 'Password (optional):' ) )
        self.lblOPassword.grid( row=2, column=0, padx=5, pady=5, sticky=tk.E )
        #self.varPassword = tk.StringVar( self.master )
        self.entOPassword = tk.Entry( self.frmODBC, textvariable=self.varPassword, show="×" )
        self.entOPassword.grid( row=2, column=1, padx=5, pady=5, sticky=tk.W )
        
        #self.frmODBC.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
        
        
        
        # Command buttons
        
        self.frmOKCancel = tk.Frame( self.frmMain, background='#ffffff' )
        self.btnDBS = ttk.Button( self.frmOKCancel, text=_( "Start scan" ), image=self.master.imgDB, compound="left", command=self.start )
        self.btnDBS.pack( side="right" )
        self.frmOKCancel.grid( row=3, column=0, columnspan=2, padx=5, pady=5 )
        
        self.currentFrame = self.frmFileDB
        
    def open_file( self ):
        if self.varDBType.get() == 'MS Access':
            if SYSTEM == 'Windows':
                FILEOPENOPTIONS = dict( defaultextension='.accdb', filetypes=[ ( 'MS Access file','*.accdb' ), ( 'MS Access 2003 file','*.mdb')])
            else:
                FILEOPENOPTIONS = dict( defaultextension='.accdb', filetypes=[ ( 'MS Access 2003 file','*.mdb')])
        else:
            FILEOPENOPTIONS = dict( defaultextension='.sqlite3', filetypes=[ ( 'SQLite3 database','*.sqlite3' ), ( 'All files','*.*')])
            
        dbfile = tkFileDialog.askopenfilename( parent=self, initialdir=expanduser( "~" ), **FILEOPENOPTIONS )
        self.varPath.set( dbfile )
        
    def start( self ):
        global TEST_FILES, TEST_DBS, DONE, CONNSTRINGS
        CONNSTRINGS = []
        self.grab_release()        
        TEST_FILES = False
        TEST_DBS = True
        DONE = False
        CONNSTRINGS.append( self.create_conn_string() )
        self.destroy()
        test()
    
    
    def create_conn_string( self ):
        dbtype = self.varDBType.get()
        if dbtype == 'SQLite':
            constring = 'sqlite+pysqlite:///%s' % self.varPath.get()
        elif dbtype == 'MS Access':
            constring = 'DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};DBQ=%s;UID=%s;PWD=%s' %\
                ( self.varPath.get(), self.varUsername.get(), self.varPassword.get() )
        elif dbtype == 'PostgreSQL':
            constring = 'postgresql+pg8000://%s:%s@%s:%s/%s' %\
                ( self.varUsername.get(), self.varPassword.get(), self.varHost.get(), self.varPort.get(), self.varDBName.get() )
        elif dbtype == 'MySQL':
            constring = 'mysql+pymysql://%s:%s@%s:%s/%s'%\
                ( self.varUsername.get(), self.varPassword.get(), self.varHost.get(), self.varPort.get(), self.varDBName.get() )
        elif dbtype == 'Oracle':
            constring = 'oracle+cx_oracle://%s:%s@%s:%s/%s' %\
                ( self.varUsername.get(), self.varPassword.get(), self.varHost.get(), self.varPort.get(), self.varDBName.get() )
        elif dbtype == 'MS SQL Server':
            if self.varUsername.get() and self.varPassword.get():
                constring = 'mssql+pyodbc://%s:%s@%s' %\
                    ( self.varUsername.get(), self.varPassword.get(), self.varDSN.get() )
            else:
                constring = 'mssql+pyodbc://%s' % self.varDSN.get()
        elif dbtype == 'ODBC':
            if self.varUsername.get() and self.varPassword.get():
                constring = r'DSN=%s;UID=%s;PWD=%s' %\
                    ( self.varUsername.get(), self.varPassword.get(), self.varDSN.get() )
            else:
                constring = r'DSN=%s' % self.varDSN.get()
        return constring
        
    def on_select( self, event=None ):
        self.currentFrame.grid_remove()
        if self.varDBType.get() in [ 'MS Access', 'SQLite' ]:
            self.currentFrame = self.frmFileDB
            self.frmFileDB.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
            if self.varDBType.get() == 'MS Access':
                self.varUsername.set( 'admin' )
            else:
                self.varUsername.set( '' )
            self.varPassword.set( '' )
        elif self.varDBType.get() in [ 'MS SQL Server', 'ODBC' ]:
            self.currentFrame = self.frmODBC
            self.frmODBC.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
            self.varUsername.set( '' )
            self.varPassword.set( '' )
        else:
            self.currentFrame = self.frmServerDB
            self.frmServerDB.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
            if self.varDBType.get() == 'PostgreSQL':
                self.varPort.set( '5432' )
            elif self.varDBType.get() == 'MySQL':
                self.varPort.set( '3306' )
            elif self.varDBType.get() == 'MS SQL Server':
                self.varPort.set( '1433' )
            elif self.varDBType.get() == 'Oracle':
                self.varPort.set( '1521' )
            self.varUsername.set( '' )
            self.varPassword.set( '' )


class PrianaConfig( tk.Toplevel ):
    def __init__( self, master, *args, **kwargs ):
        tk.Toplevel.__init__( self, master, *args, **kwargs )
        self.master = master
        self.resizable( 0, 0 )
        self.grab_set()
        self.tk.call( 'wm', 'iconphoto', self._w, master.imgicon )
        self.tk.call( 'wm', 'title', self._w, _( 'Configure database connection' ) )
        
        
        self.PSQL_CON_STRING = 'postgresql+pg8000://%(user)s:%(password)s@%(host):%(port)s/%(dbname)s'
        self.MYSQL_CON_STRING = 'mysql+pymysql://%(user)s:%(password)s@%(host):%(port)s/%(dbname)s'
        
        self.SQLITE_CON_STRING = 'sqlite+pysqlite:///%(path)s'
        
        self.frmMain = tk.Frame( self, background='#ffffff' )
        self.frmMain.pack()        
        
        self.varDBType = tk.StringVar( self.master )
        self.varDBType.set( DBTYPES[ 0 ] )
        
        self.lblDBType = tk.Label( self.frmMain, background='#ffffff', text=_( 'Select a database type:' ) )
        self.lblDBType.grid( row=0, column=0 )
        self.optDBType = tk.OptionMenu( self.frmMain, self.varDBType, *DBTYPES, command=self.on_select )
        self.optDBType.grid( row=0, column=1 )
        
        # File type frame
        
        self.frmFileDB = tk.Frame( self.frmMain, background='#ffffff' )
        self.lblPath = tk.Label( self.frmFileDB, background='#ffffff', text=_( 'Path to database file:' ) )
        self.lblPath.grid( row=0, column=0, padx=5, pady=5, sticky=tk.E )
        
        self.frmSelectPath = tk.Frame( self.frmFileDB, background='#ffffff' )
        self.frmSelectPath.grid( row=0, column=1, padx=5, pady=5, sticky=tk.W )
        
        self.varPath = tk.StringVar( self.master )
        self.entPath = tk.Entry( self.frmSelectPath, textvariable=self.varPath )
        self.entPath.pack( side='left' )
        self.imgSelectPath = itk.PhotoImage( file=IMGOPEN )
        self.btnSelectPath = ttk.Button( self.frmSelectPath, image=self.imgSelectPath, command=self.open_file )
        self.btnSelectPath.pack( side='right' )
        
        self.lblFUsername = tk.Label( self.frmFileDB, background='#ffffff', text=_( 'Username (optional):' ) )
        self.lblFUsername.grid( row=1, column=0, padx=5, pady=5, sticky=tk.E )
        self.varUsername = tk.StringVar( self.master )
        self.entFUsername = tk.Entry( self.frmFileDB, textvariable=self.varUsername )
        self.entFUsername.grid( row=1, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        self.lblFPassword = tk.Label( self.frmFileDB, background='#ffffff', text=_( 'Password (optional):' ) )
        self.lblFPassword.grid( row=2, column=0, padx=5, pady=5, sticky=tk.E )
        self.varPassword = tk.StringVar( self.master )
        self.entFPassword = tk.Entry( self.frmFileDB, textvariable=self.varPassword, show="×" )
        self.entFPassword.grid( row=2, column=1, padx=5, pady=5, sticky=tk.W )
        
        self.frmFileDB.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
        
        # Server type frame
        
        self.frmServerDB = tk.Frame( self.frmMain, background='#ffffff' )
        self.lblHost = tk.Label( self.frmServerDB, background='#ffffff', text=_( 'Host and port:' ) )
        self.lblHost.grid( row=0, column=0, padx=5, pady=5, sticky=tk.E )
        
        self.frmHostPort = tk.Frame( self.frmServerDB, background='#ffffff' )
        self.frmHostPort.grid( row=0, column=1, padx=5, pady=5, sticky=tk.W )
        
        self.varHost = tk.StringVar( self.master )
        self.varHost.set( 'localhost' )
        self.entHost = tk.Entry( self.frmHostPort, textvariable=self.varHost, width=15 )
        self.entHost.pack( side='left' )
        
        self.varPort = tk.StringVar( self.master )
        self.entPort = tk.Entry( self.frmHostPort, textvariable=self.varPort, width=4 )
        self.entPort.pack( side='right' )
        
        self.lblSUsername = tk.Label( self.frmServerDB, background='#ffffff', text=_( 'Username:' ) )
        self.lblSUsername.grid( row=1, column=0, padx=5, pady=5, sticky=tk.E )
        #self.varUsername = tk.StringVar( self.master )
        self.entSUsername = tk.Entry( self.frmServerDB, textvariable=self.varUsername )
        self.entSUsername.grid( row=1, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        self.lblSPassword = tk.Label( self.frmServerDB, background='#ffffff', text=_( 'Password:' ) )
        self.lblSPassword.grid( row=2, column=0, padx=5, pady=5, sticky=tk.E )
        #self.varPassword = tk.StringVar( self.master )
        self.entSPassword = tk.Entry( self.frmServerDB, textvariable=self.varPassword, show="×" )
        self.entSPassword.grid( row=2, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        self.lblDBName = tk.Label( self.frmServerDB, background='#ffffff', text=_( 'Database name:' ) )
        self.lblDBName.grid( row=3, column=0, padx=5, pady=5, sticky=tk.E )
        self.varDBName = tk.StringVar( self.master )
        self.entDBName = tk.Entry( self.frmServerDB, textvariable=self.varDBName )
        self.entDBName.grid( row=3, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        #self.frmServerDB.grid( row=2, column=0, columnspan=2, padx=5, pady=5 )
        
        # ODBC type frame
        
        self.frmODBC = tk.Frame( self.frmMain, background='#ffffff' )
        
        DSNs = pyodbc.dataSources().keys()
        self.varDSN = tk.StringVar( self.master )
	try:        
		self.varDSN.set( DSNs[ 0 ] )
	except:
		srcs = _( 'No available sources' )
		self.varDSN.set( srcs )
		DSNs = [ srcs ]
        
        self.lblDSN = tk.Label( self.frmODBC, background='#ffffff', text=_( 'Data Source Name (DSN):' ) )
        self.lblDSN.grid( row=0, column=0 )
        self.optDSN = apply( tk.OptionMenu, ( self.frmODBC, self.varDSN ) + tuple( DSNs ) ) # tk.OptionMenu(  ) #, command=self.on_select )
        self.optDSN.grid( row=0, column=1 )
        
        self.lblOUsername = tk.Label( self.frmODBC, background='#ffffff', text=_( 'Username (optional):' ) )
        self.lblOUsername.grid( row=1, column=0, padx=5, pady=5, sticky=tk.E )
        #self.varUsername = tk.StringVar( self.master )
        self.entOUsername = tk.Entry( self.frmODBC, textvariable=self.varUsername )
        self.entOUsername.grid( row=1, column=1, padx=5, pady=5, sticky=tk.W )
        
        
        self.lblOPassword = tk.Label( self.frmODBC, background='#ffffff', text=_( 'Password (optional):' ) )
        self.lblOPassword.grid( row=2, column=0, padx=5, pady=5, sticky=tk.E )
        #self.varPassword = tk.StringVar( self.master )
        self.entOPassword = tk.Entry( self.frmODBC, textvariable=self.varPassword, show="×" )
        self.entOPassword.grid( row=2, column=1, padx=5, pady=5, sticky=tk.W )
        
        #self.frmODBC.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
        
        
        
        # Command buttons
        
        self.frmOKCancel = tk.Frame( self.frmMain, background='#ffffff' )
        self.btnDBS = ttk.Button( self.frmOKCancel, text=_( "Start scan" ), image=self.master.imgDB, compound="left", command=self.start )
        self.btnDBS.pack( side="right" )
        self.frmOKCancel.grid( row=3, column=0, columnspan=2, padx=5, pady=5 )
        
        self.currentFrame = self.frmFileDB
        
    def open_file( self ):
        if self.varDBType.get() == 'MS Access':
            if SYSTEM == 'Windows':
                FILEOPENOPTIONS = dict( defaultextension='.accdb', filetypes=[ ( 'MS Access file','*.accdb' ), ( 'MS Access 2003 file','*.mdb')])
            else:
                FILEOPENOPTIONS = dict( defaultextension='.accdb', filetypes=[ ( 'MS Access 2003 file','*.mdb')])
        else:
            FILEOPENOPTIONS = dict( defaultextension='.sqlite3', filetypes=[ ( 'SQLite3 database','*.sqlite3' ), ( 'All files','*.*')])
            
        dbfile = tkFileDialog.askopenfilename( parent=self, initialdir=expanduser( "~" ), **FILEOPENOPTIONS )
        self.varPath.set( dbfile )
        
    def start( self ):
        global TEST_FILES, TEST_DBS, DONE, CONNSTRINGS
        CONNSTRINGS = []
        self.grab_release()        
        TEST_FILES = False
        TEST_DBS = True
        DONE = False
        CONNSTRINGS.append( self.create_conn_string() )
        self.destroy()
        test()
    
    
    def create_conn_string( self ):
        dbtype = self.varDBType.get()
        if dbtype == 'SQLite':
            constring = 'sqlite+pysqlite:///%s' % self.varPath.get()
        elif dbtype == 'MS Access':
            constring = 'DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};DBQ=%s;UID=%s;PWD=%s' %\
                ( self.varPath.get(), self.varUsername.get(), self.varPassword.get() )
        elif dbtype == 'PostgreSQL':
            constring = 'postgresql+pg8000://%s:%s@%s:%s/%s' %\
                ( self.varUsername.get(), self.varPassword.get(), self.varHost.get(), self.varPort.get(), self.varDBName.get() )
        elif dbtype == 'MySQL':
            constring = 'mysql+pymysql://%s:%s@%s:%s/%s'%\
                ( self.varUsername.get(), self.varPassword.get(), self.varHost.get(), self.varPort.get(), self.varDBName.get() )
        elif dbtype == 'Oracle':
            constring = 'oracle+cx_oracle://%s:%s@%s:%s/%s' %\
                ( self.varUsername.get(), self.varPassword.get(), self.varHost.get(), self.varPort.get(), self.varDBName.get() )
        elif dbtype == 'MS SQL Server':
            if self.varUsername.get() and self.varPassword.get():
                constring = 'mssql+pyodbc://%s:%s@%s' %\
                    ( self.varUsername.get(), self.varPassword.get(), self.varDSN.get() )
            else:
                constring = 'mssql+pyodbc://%s' % self.varDSN.get()
        elif dbtype == 'ODBC':
            if self.varUsername.get() and self.varPassword.get():
                constring = r'DSN=%s;UID=%s;PWD=%s' %\
                    ( self.varUsername.get(), self.varPassword.get(), self.varDSN.get() )
            else:
                constring = r'DSN=%s' % self.varDSN.get()
        return constring
        
    def on_select( self, event=None ):
        self.currentFrame.grid_remove()
        if self.varDBType.get() in [ 'MS Access', 'SQLite' ]:
            self.currentFrame = self.frmFileDB
            self.frmFileDB.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
            if self.varDBType.get() == 'MS Access':
                self.varUsername.set( 'admin' )
            else:
                self.varUsername.set( '' )
            self.varPassword.set( '' )
        elif self.varDBType.get() in [ 'MS SQL Server', 'ODBC' ]:
            self.currentFrame = self.frmODBC
            self.frmODBC.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
            self.varUsername.set( '' )
            self.varPassword.set( '' )
        else:
            self.currentFrame = self.frmServerDB
            self.frmServerDB.grid( row=1, column=0, columnspan=2, padx=5, pady=5 )
            if self.varDBType.get() == 'PostgreSQL':
                self.varPort.set( '5432' )
            elif self.varDBType.get() == 'MySQL':
                self.varPort.set( '3306' )
            elif self.varDBType.get() == 'MS SQL Server':
                self.varPort.set( '1433' )
            elif self.varDBType.get() == 'Oracle':
                self.varPort.set( '1521' )
            self.varUsername.set( '' )
            self.varPassword.set( '' )
            
        
CONNSTRINGS = []        
def test():
    global CONNSTRINGS, START
    if TEST:
        START = datetime.now()
        parseuser = get_parser( 'txt' )
        pa = GDPRParser( parseuser, PASSWORD )
        pa.start()
        
        agguser = get_aggregator()
        ag = GDPRAggregator( agguser, PASSWORD )
        ag.start()
        
        fsuser = get_file_searcher()
        fs = FileSearcher( fsuser, PASSWORD )
        if TEST_FILES:
            fs.start()
        else:
            fs.send_msg( get_aggregator(), 'Nothing to search!', 'report' )
        
        
        dsuser = get_db_searcher()
        ds = DBSearcher( dsuser, PASSWORD )
        if TEST_DBS:
            #CONNSTRINGS = []

            PSQL_TEST = 'postgresql+pg8000://markus:lozinka@localhost:5432/markus'
            SQLITE_TEST = 'sqlite+pysqlite:///test_sqlite.db'
            MYSQL_TEST = 'mysql+pymysql://markus:lozinka@localhost/test'
            
            '''CONNSTRINGS.append( PSQL_TEST )'''
            '''CONNSTRINGS.append( SQLITE_TEST )'''
            '''CONNSTRINGS.append( MYSQL_TEST )
            CONNSTRINGS.append( MSACCESSOLD_TEST )
            CONNSTRINGS.append( MSACCESSOLD_TEST2 )'''
            ds.start()
        else:
            ds.send_msg( get_aggregator(), 'Nothing to search!', 'report' )



class Spawner( subprocess.Popen ):
    '''Simple platform independent spawner for shell-like processes
    (inherits subprocess.Popen)

    Based on:

    http://code.activestate.com/recipes/440554/ (r10)
    '''
    message = "Other end disconnected!"

    def recv(self, maxsize=None):
        '''receive from stdout
        Usage: instance.recv( maxsize )
        maxsize - optional number of bytes to receive'''
        return self._recv('stdout', maxsize)
    
    def recv_err(self, maxsize=None):
        '''receive from sterr
        Usage: instance.recv_err( maxsize )
        maxsize - optional number of bytes to receive'''
        return self._recv('stderr', maxsize)

    def send_recv(self, input='', maxsize=None):
        '''Send input, and receive both stdout and stderr
        Usage: instance.send_recv( input, maxsize )
        input - optional input string
        maxsize - optional number of bytes to receive'''
        return self.send(input), self.recv(maxsize), self.recv_err(maxsize)

    def get_conn_maxsize(self, which, maxsize):
        '''Get the maximal size of connection buffer
        Usage: instance.get_conn_maxsize( which, maxsize )
        which - connection to check
        maxsize - maxsize as wanted by the process'''
        if maxsize is None:
            maxsize = 1024
        elif maxsize < 1:
            maxsize = 1
        return getattr(self, which), maxsize
    
    def _close(self, which):
        '''Private method to close the process connection
        Usage: instance._close( which )
        which - connection to close'''
        getattr(self, which).close()
        setattr(self, which, None)
    
    def get(self, t=.1, e=1, tr=5):
        '''Get the output (stdin + stderr) after a sent line
        Usage: instance.get( t, e, tr )
        t - timeout in seconds (default 0.2)
        e - raise exceptions? (default: 1 )
        tr - number of tries (default=5)'''
        if tr < 1:
            tr = 1
        x = time.time()+t
        y = []
        r = ''
        pr = self.recv
        while time.time() < x or r:
            r = pr()
            if r is None:
                if e:
                    raise Exception(self.message)
                else:
                    break
            elif r:
                y.append(r)
            else:
                time.sleep(max((x-time.time())/tr, 0))
        res = ''.join(y) + self.endline
        pr = self.recv_err
        if tr < 1:
            tr = 1
        x = time.time()+t
        y = []
        r = ''
        while time.time() < x or r:
            r = pr()
            if r is None:
                if e:
                    raise Exception(self.message)
                else:
                    break
            elif r:
                y.append(r)
            else:
                time.sleep(max((x-time.time())/tr, 0))
        res += ''.join(y)
        return res
        
    def send_all(self, data):
        '''Send data to the process
        Usage: instance.send_all( data )
        data - data to be transmitted'''
        while len(data):
            sent = self.send(data)
            if sent is None:
                raise Exception(self.message)
            data = buffer(data, sent)
    
    def sendline(self, line):
        '''Send data to the process with a platform dependend newline
        character which is appended to the data
        Usage: instance.sendline( line )
        line - string (without newline) to be sent to the process'''
        self.send_all(line + self.endline)

    if subprocess.mswindows:
        '''Windows specific attributes and methods'''
        endline = "\r\n"

        def send(self, input):
            '''Send input to stdin
            Usage: instance.send( input )
            input - input to be sent'''
            if not self.stdin:
                return None

            try:
                x = msvcrt.get_osfhandle(self.stdin.fileno())
                (errCode, written) = WriteFile(x, input)
            except ValueError:
                return self._close('stdin')
            except (subprocess.pywintypes.error, Exception), why:
                if why[0] in (109, errno.ESHUTDOWN):
                    return self._close('stdin')
                raise

            return written

        def _recv(self, which, maxsize):
            '''Private method for receiving data from process
            Usage: instance( which, maxsize (
            which - connection to receive output from
            maxsize - maximm size of buffer to be received'''
            conn, maxsize = self.get_conn_maxsize(which, maxsize)
            if conn is None:
                return None
            
            try:
                x = msvcrt.get_osfhandle(conn.fileno())
                (read, nAvail, nMessage) = PeekNamedPipe(x, 0)
                if maxsize < nAvail:
                    nAvail = maxsize
                if nAvail > 0:
                    (errCode, read) = ReadFile(x, nAvail, None)
            except ValueError:
                return self._close(which)
            except (subprocess.pywintypes.error, Exception), why:
                if why[0] in (109, errno.ESHUTDOWN):
                    return self._close(which)
                raise
            
            if self.universal_newlines:
                read = self._translate_newlines(read)
            return read

    else:
        '''*NIX specific attributes and methods'''
        endline = "\n"

        def send(self, input):
            '''Send input to stdin
            Usage: instance.send( input )
            input - input to be sent'''
            if not self.stdin:
                return None

            if not select.select([], [self.stdin], [], 0)[1]:
                return 0

            try:
                written = os.write(self.stdin.fileno(), input)
            except OSError, why:
                if why[0] == errno.EPIPE: #broken pipe
                    return self._close('stdin')
                raise

            return written

        def _recv(self, which, maxsize):
            '''Private method for receiving data from process
            Usage: instance( which, maxsize (
            which - connection to receive output from
            maxsize - maximm size of buffer to be received'''
            conn, maxsize = self.get_conn_maxsize(which, maxsize)
            if conn is None:
                return None
            
            flags = fcntl.fcntl(conn, fcntl.F_GETFL)
            if not conn.closed:
                fcntl.fcntl(conn, fcntl.F_SETFL, flags| os.O_NONBLOCK)
            
            try:
                if not select.select([conn], [], [], 0)[0]:
                    return ''
                
                r = conn.read(maxsize)
                if not r:
                    return self._close(which)
    
                if self.universal_newlines:
                    r = self._translate_newlines(r)
                return r
            finally:
                if not conn.closed:
                    fcntl.fcntl(conn, fcntl.F_SETFL, flags)

# From: https://github.com/pyinstaller/pyinstaller/wiki/Recipe-subprocess
# Create a set of arguments which make a ``subprocess.Popen`` (and
# variants) call work with or without Pyinstaller, ``--noconsole`` or
# not, on Windows and Linux. Typical use::
#
#   subprocess.call(['program_to_run', 'arg_1'], **subprocess_args())
#
# When calling ``check_output``::
#
#   subprocess.check_output(['program_to_run', 'arg_1'],
#                           **subprocess_args(False))
def subprocess_args(include_stdout=True):
    # The following is true only on Windows.
    if hasattr(subprocess, 'STARTUPINFO'):
        # On Windows, subprocess calls will pop up a command window by default
        # when run from Pyinstaller with the ``--noconsole`` option. Avoid this
        # distraction.
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        # Windows doesn't search the path by default. Pass it an environment so
        # it will.
        env = os.environ
    else:
        si = None
        env = None

    # ``subprocess.check_output`` doesn't allow specifying ``stdout``::
    #
    #   Traceback (most recent call last):
    #     File "test_subprocess.py", line 58, in <module>
    #       **subprocess_args(stdout=None))
    #     File "C:\Python27\lib\subprocess.py", line 567, in check_output
    #       raise ValueError('stdout argument not allowed, it will be overridden.')
    #   ValueError: stdout argument not allowed, it will be overridden.
    #
    # So, add it only if it's needed.
    if include_stdout:
        ret = {'stdout': subprocess.PIPE}
    else:
        ret = {}

    # On Windows, running this from the binary produced by Pyinstaller
    # with the ``--noconsole`` option requires redirecting everything
    # (stdin, stdout, stderr) to avoid an OSError exception
    # "[Error 6] the handle is invalid."
    ret.update({'stdin': subprocess.PIPE,
                'stderr': subprocess.PIPE,
                'startupinfo': si,
                'env': env })
    return ret
                    
class rekodr:
    def __init__( self, path='rekodr.exe', args='Also sprach Zaratustra' ):
        if SYSTEM == 'Linux':
            path = './' + path
        self.engine = Spawner( shlex.split( path + ' ' + args ), **subprocess_args() ) # stdin=PIPE, stdout=PIPE, stderr=PIPE, 
        sleep( 0.5 )
        self.state = self.engine.get().decode( 'utf-8' ).strip()

    def interact( self, answer ):
        answer = answer.strip()
        if answer[ -1 ] != '.':
            query += '.'
        self.engine.sendline( answer )
        self.state = self.engine.get( e=0 ).decode( 'utf-8' ).strip()

import pickle
import ctypes

FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_NORMAL = 0x80

def write_hidden( file_name, data ):
    """
    Cross platform hidden file writer.
    """
    if os.name == 'nt':
        ret = ctypes.windll.kernel32.SetFileAttributesW( file_name,
                                                         FILE_ATTRIBUTE_NORMAL )
        if not ret: # There was an error.
            raise ctypes.WinError()
    
    # For *nix add a '.' prefix.
    #prefix = '.' if os.name != 'nt' else ''
    #file_name = prefix + file_name

    # Write file.
    with open( file_name, 'w' ) as f:
        f.write( data )

    # For windows set file attribute.
    
    if os.name == 'nt':
        ret = ctypes.windll.kernel32.SetFileAttributesW( file_name,
                                                         FILE_ATTRIBUTE_HIDDEN )
        if not ret: # There was an error.
            raise ctypes.WinError()
        
class cpu_manager:
    def __init__( self, num=1 ):
        self.num = num

    def verify( self ):
        return True
        fl = open( CACHE_FILE )
        data = fl.read()
        fl.close()
        pck = decode( data, AKEY )
        lst = pickle.loads( pck )
        unique, username = get_cpu_id()
        cpu_id = '%s-%s' % ( unique, username )
        ids = dict( lst )
        mtime = datetime.fromtimestamp( os.path.getmtime( CACHE_FILE ) )
        cputime = max( ids.values() )
        onesec = timedelta( 0, 5, 0 )
        print mtime, cputime, onesec, mtime - cputime
        if abs( mtime - cputime ) > onesec:
            error( _( 'Error!' ), _( "The file system structure of the program has been corrupted. Please contact support!" )  )
        if cpu_id in ids.keys():
            return True
        elif len( lst ) <= self.num: # = since default one added
            lst.append( ( cpu_id, datetime.now() ) )
            pck = pickle.dumps( lst )
            cip = encode( pck, AKEY )
            write_hidden( CACHE_FILE, cip )
            return True
        return False
    

def which( program ):
    def is_exe( fpath ):
        return os.path.isfile( fpath ) and os.access( fpath, os.X_OK )

    fpath, fname = os.path.split( program )
    if fpath:
        if is_exe( program ):
            return program
    else:
        for path in [ '.' ] + os.environ[ "PATH" ].split( os.pathsep ):
            exe_file = os.path.join( path, program )
            if is_exe(exe_file):
                return exe_file

    return None

def check_requirements():
    if SYSTEM == 'Linux' or SYSTEM == 'Darwin':
        if not which( 'mdb-tables' ) or not which( 'mdb-export' ):
            error( _( 'Software requirements' ), _( 'The program needs MDB Tools to be installed in order to run properly.' ) )
        if not which( 'rekodr.exe' ):
            error( _( 'Error!' ), _( "The file system structure of the program has been corrupted. Please contact support!" ) )
    elif SYSTEM == 'Windows':
        from winreg import OpenKey, QueryValueEx, HKEY_LOCAL_MACHINE
        try:
            key = OpenKey( HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' )
            x = QueryValueEx( key, 'bld' )[ 0 ]
        except Exception as e:
            print 1, e
            try:
                key = OpenKey( HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x86' )
                x = QueryValueEx( key, 'bld' )[ 0 ]
            except Exception as e:
                print 2, e
                try:
                    res = yesno( _( 'Software requirements' ), _( 'The program needs VC++ Redistributable to be installed in order to run properly. Do you want to install it now?' ) )
                    if res == 'yes':
                        if os64bit():
                            inst = 'VC_redist_x64.exe'
                        else:
                            inst = 'VC_redist_x86.exe'
                        subprocess.call( [ os.path.join( 'installers', inst ) ] )
                    sys.exit( 0 ) # I EDITED THIS TO EXIT IF REQUIREMENTS ARE NOT TO BE INTALLED
                except Exception as e:
                    print 3, e
                    sys.exit( 0 )
        try:
            key = OpenKey( HKEY_LOCAL_MACHINE, r'SOFTWARE\ODBC\ODBCINST.INI\Microsoft Access Driver (*.mdb, *.accdb)' )
            x = QueryValueEx( key, 'APILevel' )[ 0 ]
        except Exception as e:
            print 4, e
            res = yesno( _( 'Software requirements' ), _( 'The program needs Microsoft Access Redistributable Database Engine to be installed in order to run properly. Do you want to install it now?' ) )
            if res == 'yes':
                if os64bit():
                    inst = 'AccessDatabaseEngine_X64.exe'
                else:
                    inst = 'AccessDatabaseEngine.exe'
                subprocess.call( [ os.path.join( 'installers', inst ) ], shell=True )
                sys.exit( 0 )


                
def os64bit():
    return platform.machine().endswith('64')                   

def error( title, msg, kill=True ):
    root = tk.Tk()
    root.withdraw()
    tkMessageBox.showerror( title, msg,  )
    if kill:
        sys.exit( 0 )

def yesno( title, msg, kill=True ):
    root = tk.Tk()
    root.withdraw()
    result = tkMessageBox.askquestion( title, msg, icon='warning' )
    if result == 'no':
        if kill:
            sys.exit( 0 )
    else:
        return result
    

LEGAL = '''
    PriAna - Privacy analysis tool based on AI
    Copyright (C) 2018  Markus Schatten, Miroslav Bača

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''
    
if __name__ == '__main__':
    multiprocessing.freeze_support()
    check_requirements()

    print LEGAL
    
    
    TEST = True

    TEST_FILES = True
    MAXFILES = 100
    HASMAX = False

    TEST_DBS = False
    
    if os.path.isfile( LOCKFILE ):
        error( _( 'Error!' ), _( "There seems to be another instance of the program running. If this isn't the case, please delete the file '%s'." % LOCKFILE ),  )
    else:
        lf = open( LOCKFILE, 'w' )
        lf.write( '1' )
        lf.close()
        del lf
    
    generateCode( 'localhost' )

    spade_platform = Process( target=main )
    spade_platform.start()


    sleep( 1 )

    app = PriAnaGUI()
    app.mainloop()
