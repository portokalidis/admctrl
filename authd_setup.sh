#!/bin/bash

DIR=/etc/authd
TMPFILE=/tmp/.authd
CLPUB=pub.key
CLPRIV=priv.key
CLKEYSZ=1024
RESCRTL=resourcectrl

generate_policy()
{
  echo "KeyNote-Version: 2" >$POLICY
  echo "Authorizer: \"POLICY\"" >>$POLICY
  echo -n "Licensees: " >>$POLICY
  cat $PUBKEY >>$POLICY
  echo "Conditions: app_domain == \"MY DOMAIN\" -> \"true\";" >> $POLICY
}

case "$1" in
  install)
		if [ "$#" -lt "2" ]; then
			INSTALLAS=$USER
		else
			INSTALLAS=$2
		fi
    if [ "$#" -gt "2" ]; then
      DIR=$3
    fi
    PUBKEY=$DIR/authd_key.pub
    PRIVKEY=$DIR/authd_key.priv
    POLICY=$DIR/policy

    echo "Creating admission control files in $DIR"
    mkdir -m 755 -p $DIR/$RESCRTL
    echo "Generating admission control keys..."
    keynote keygen rsa-base64: $CLKEYSZ $PUBKEY $PRIVKEY
    chmod 644 $PUBKEY
    chmod 600 $PRIVKEY
    echo "Generating default policy file..."
    generate_policy
    echo "Creating $TMPFILE file for IPC..."
    touch $TMPFILE
    chmod 644 $TMPFILE
    echo "Setting ownership of files to $INSTALLAS..."
    chown -R $INSTALLAS $DIR $TMPFILE
    exit 0
    ;;
  uninstall)
    if [ "$#" -gt "2" ]; then
      DIR=$2
    fi
    PUBKEY=$DIR/authd_key.pub
    PRIVKEY=$DIR/authd_key.priv
    POLICY=$DIR/policy

    echo "Removing admission control files located in $DIR..."
    rm -f $PUBKEY $PRIVKEY $POLICY
    rmdir --ignore-fail-on-non-empty $DIR/$RESCRTL
    rmdir --ignore-fail-on-non-empty $DIR
    echo "Removing $TMPFILE file..."
    rm -f $TMPFILE
    exit 0
    ;;
  keys)
    if [ "$#" -gt "1" ]; then
      CLKEYSZ=$2
    fi
    if [ "$#" -gt "2" ]; then
      CLPUB=$3
    fi
    if [ "$#" -gt "3" ]; then
      CLPRIV=$4
    fi
    echo "Creating key pair..."
    rm -f $CLPUB $CLPRIV
    keynote keygen rsa-base64: $CLKEYSZ $CLPUB $CLPRIV
    exit 0
    ;;
  policy)
		if [ "$#" -lt "2" ]; then
			INSTALLAS=$USER
		else
			INSTALLAS=$2
		fi
    if [ "$#" -gt "2" ]; then
      DIR=$3
    fi
    PUBKEY=$DIR/authd_key.pub
    POLICY=$DIR/policy

    mkdir -m 755 -p $DIR
    echo "Generating default policy file..."
    generate_policy
    exit 0
    ;;
  credentials)
    if [ "$#" -lt "4" ] ; then
      echo "Usage: $0 credentials public_key conditions output [path]"
      exit 1
    fi
    if [ "$#" -gt "4" ]; then
      DIR=$5
    fi
    PUBKEY=$DIR/authd_key.pub
    PRIVKEY=$DIR/authd_key.priv

    if  [[ ! -r "$2" || ! -r  "$3" || ! -r "$PUBKEY" || ! -r "$PRIVKEY" ]] ; then
      echo "Check that the files $2,$3,$PUBKEY,$PRIVKEY exist and you have permissions to read them"
      exit 1
    fi

		TMP=`mktemp creds-XXXXXX` || exit 1
    rm -f $TMP 
    echo "KeyNote-Version: 2" >$TMP
    echo -n "Authorizer: " >>$TMP
    cat $PUBKEY >>$TMP
    echo -n "Licensees: " >>$TMP
    cat $2 >>$TMP
    echo -n "Conditions: " >> $TMP
    cat $3 >> $TMP
    echo -n "Signature: " >>$TMP
    rm -f $4
    cat $TMP > $4
    keynote sign "sig-rsa-sha1-base64:" $TMP $PRIVKEY >> $4
    rm -f $TMP
    exit 0
    ;;
  *)
    echo "Usage: $0 install|uninstall|policy|keys|credentials"
		echo "  install     [user id] [pathname]"
    echo "     Install all necessary files for admission control in 'pathname'"
    echo "     and set ownership to 'user id'.pathname is '/etc/authd' by default."
		echo "  uninstall   [pathname]"
    echo "     Remove files installed by install in 'pathname'."
		echo "  policy      [user id] [pathname]"
    echo "     Create a new default policy file in 'pathname' and set ownership"
    echo "     to 'user id'."
		echo "  keys      [key size] [pubk name] [privk name]"
    echo "     Generate a public/private key pair. The length of "
    echo "     of the key will be 'key size', default 1024 bits. Write public"
    echo "     key to file 'pubk name' and private to 'privk name', default "
    echo "     'pub.key' and 'priv.key'"
		echo "  credentials (public key) (conditions) (output) [path]"
    echo "     Generate credentials for licensee in 'public key' using"
    echo "     'conditions' and store it to file 'output'. Optionally 'path'"
    echo "     is the location of admission control keys."
		echo ""
    exit 1
    ;;
esac

exit 0
