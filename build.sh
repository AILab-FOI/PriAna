
SYSTEM=$1

DEST=$2

SKIP=$3

if [ $SYSTEM = 'win' ]
then
    PYINSTALLER=/cygdrive/c/Python27/Scripts/pyinstaller.exe
    REKODR=rekodr.exe
    DIST=dist-win
    if ! [ -f "$PYINSTALLER" ]
    then
	echo "Cannot find pyinstaller. Please install it or edit build.sh to find the pyinstaller executable."
	exit
    fi
else
    PYINSTALLER=pyinstaller
    REKODR=rekodr.exe
    DIST=dist-linux
fi




if [ $SKIP = 'no' ]
then
	echo "Compiling rekodr ..."

	swipl -o $REKODR --goal=kreni -c rekodr.P --stand_alone=true

	echo "Done compiling rekodr!"
fi

if [ $SYSTEM = 'win' ]
then
	DISTRO=$DEST/windows-bin
	if [ $SKIP = 'no' ]
	then
		echo "We are on Windoze, packaging extractor ..."
		pkg package.json --targets node9-win-x64
		echo "Done packaging extractor!"
	fi
else
	DISTRO=$DEST/linux-bin
fi

if [ $SKIP = 'no' ]
then
	echo "Refreshing destination folder ..."
	rm -rf $DISTRO
	mkdir $DISTRO
	echo "Done!"
fi


echo "Running pyinstaller ..."
#  
#$PYINSTALLER --onefile --noconsole --distpath=$DIST --hidden-import='textract.parsers.csv_parser' --hidden-import='textract.parsers.doc_parser' --hidden-import='textract.parsers.docx_parser' --hidden-import='textract.parsers.eml_parser' --hidden-import='textract.parsers.epub_parser' --hidden-import='textract.parsers.gif_parser' --hidden-import='textract.parsers.json_parser' --hidden-import='textract.parsers.html_parser' --hidden-import='textract.parsers.mp3_parser' --hidden-import='textract.parsers.msg_parser' --hidden-import='textract.parsers.odt_parser' --hidden-import='textract.parsers.ogg_parser' --hidden-import='textract.parsers.png_parser' --hidden-import='textract.parsers.jpg_parser' --hidden-import='textract.parsers.pptx_parser' --hidden-import='textract.parsers.ps_parser' --hidden-import='textract.parsers.rtf_parser' --hidden-import='textract.parsers.tiff_parser' --hidden-import='textract.parsers.txt_parser' --hidden-import='textract.parsers.pdf_parser' --hidden-import='textract.parsers.wav_parser' --hidden-import='textract.parsers.xlsx_parser' --hidden-import='textract.parsers.xls_parser' --hidden-import='PIL._tkinter_finder' --hidden-import='nltk.chunk.named_entity' --hidden-import='pymysql' --hidden-import='pg8000'  --hidden-import='win32com' --hidden-import='face_recognition_models' --icon=resources/prana.ico -n 'priana.exe' priana.py # add this if needed , --hidden-import='numpy.core.multiarray'

$PYINSTALLER --onefile --noconsole --distpath=$DIST --icon=resources/prana.ico -n 'priana.exe' priana.exe.spec 
echo "Done running pyinstaller!" 
 
 
echo "Copying pyinstaller files to destination ..."
cp -r $DIST/* $DISTRO
rm -rf $DIST
echo "Done!"

if [ $SKIP = 'no' ]
then
	echo "Copying resources to destination ..."
	cp -r resources $DISTRO
	mkdir $DISTRO/data
	echo "Done!"

	echo "Copying libs to destination ..."
	cp -r libs $DISTRO
	rm -rf $DISTRO/face_recognition_models
	echo "Done!"
else
	rm $DISTRO/data/*
fi

if [ $SYSTEM = 'win' ]
then
	if [ $SKIP = 'no' ]
	then 
		echo "We are on Windoze, copying binaries ..."
		cp -r bin $DISTRO
		echo "... installers ..."
		cp -r installers $DISTRO
		echo "... extractor exe ..."
		cp extract.exe $DISTRO
		echo "... dlls ..."
		cp *.dll $DISTRO
		echo "... magic ..."
		cp magic.mgc $DISTRO
		echo "Done!"
	fi
	echo "Creating PriAna binary ..."
	cp $DISTRO/priana.exe .
	/cygdrive/c/Program\ Files/AutoHotkey/Compiler/Ahk2Exe.exe /in main.ahk /out PriAna.exe /icon resources/prana.ico /mpress 0
	cp PriAna.exe $DEST
	rm $DISTRO/priana.exe
	echo "Done!"
#else
    #mv $DISTRO/priana $DISTRO/priana.exe
    #chmod +x $DISTRO/*.exe
fi

if [ $SKIP = 'no' ]
then
       	echo "Copying rekodr ..."
	cp $REKODR $DISTRO
	echo "Copying legal ..."
	cp -r LICENSE.gpl $DISTRO
fi
echo "Done finally!!!"


