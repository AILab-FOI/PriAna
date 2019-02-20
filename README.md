PriAna - Privacy Analysis
=========================

![PriAna GDPR](https://raw.githubusercontent.com/AILab-FOI/PriAna/master/resources/banner.png)

Intro
-----
PriAna is a privacy analysis tool based on various data science and artificial
intelligence techniques that tries to identify privacy related data on your
computer. It scans for various file types and supports various database
systems including MS Access, MS SQL Server, MySQL, ODBC, Oracle, PostgreSQL
and SQLite. It can be a valuable tool for GDPR assesment and audit.

Supported filetypes
-------------------
PriAna uses various NLP techniques to find privacy related content (in the current
version English and Croatian words are supported, but support for other languages
is pending) from numerous filetypes including but not limited to csv, doc, docx,
eml, epub, gif, jpg, jpeg, json, html, htm, mp3, msg, odt, ogg, pdf, png, pptx,
ps, rtf, tiff, tif, txt, wav, xlsx, xls, mdb, rtf, and html.

In addition to filetypes it also scans for MIME types so renamed files are scanned
as well. Besides textual formats it extracts textual information from images using
OCR as well as speech from audio files using speech to text.

It identifies various archive types including images of virtual machines: ovf, ova,
box, vmdk, vdi, vhd, img, raw, iso, zip, rar, tar, 7z. In the current version such
archives have to be extracted and scanned manually.

Supported search
----------------
PriAna searches for privacy related keywords (currently defined in priana.py),
education related keywords and sexual orientation related keywords. It identifies
emails, Croatian social security numbers (OIB and JMBG), IP addresses, MAC addresses,
GPS coordinates and bank card numbers.

Using NLP it identifies names and locations, and using face detection it identifies
images with human faces on them.

Supported platforms
-------------------
PriAna has been tested on Linux and Windows. In case you encounter problems
on any of these platforms, please file an issue on GitHub, we will look into it
as soon as possible. If you manage to run PriAna on any other platform, please
let us know, we are happily accepting patches ;-)

Reporting
---------
PriAna outputs a report of all found files or tables in databases categorized into
high, medium and low risk items. The output reports are stored in the data directory
of PriAna.

Recommendation system (Croatian only)
-------------------------------------
PriAna also implements a small expert system for GDPR compliance currently only in
Croatian that can help you asses all found data. This expert system is by no means
a full audit and it does not guarantee in any way that you are GDPR compliant even
if it states so!

Running from source
-------------------
In order to run PriAna from source you will need a working Python (>= 2.7) environment
including a number of modules: SPADE (version 2), textract, gettext, ZODB, magic,
nltk, SQLAlchemy, pyODBC, multiprocessing, psutil, tkinter, ttk, tkMessageBox,
tkFileDialog, PIL, pickle, ctypes and face_recognition.

To run the recommendation expert system you will need a working installation of SWI
Prolog

In order to use the database scanning features on Linux you will need to install UnixODBC,
MDB-tables, MDB-export.

On Windows you will need VC++ Redistributable and Microsoft Access Redistributable Database
Engine. Other dependencies include AntiWord, Oracle's instant client, pdftools,
Tesseract-OCR and textract's node version, as well as a number of DLLs included in the
source.

Building the binary
-------------------
To build the binary a shell script is included. You will need pyinstaller in
order to build a working executable. On Windows you will need to run it through
CygWin and need to install AutoHotKey.

The 'build.sh' script accepts 3 arguments:
1. Platform (linux or win)
2. Destination directory where the bineries are to be stored
3. Optional skip if the value is no then all is to be build else the compile of
the expert system is skipped and the destination folder is deleted in full.

Pre-built binaries
------------------
A pre-built binary is available for Windows (will be online soon):
http://ai.foi.hr/priana-win.zip

As well as for Linux (Ubuntu):
http://ai.foi.hr/priana-linux.tar.xz

