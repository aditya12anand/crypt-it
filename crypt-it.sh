#!/bin/bash

logo()
{
	#Encrypt / Decrypt

	echo "
    ____  _____  __   __  ____  _______      ________ _________
   /    \ |  _ \ \ \_/ / |  _ \ |__ __|      |__  __| |___ ___|
  |  /\_| |  = /  \   /  |  __/   | |   ____   | |       | |
  |  \/-\ | |\ \   | |   | |      | |  |____| _| |__     | |
   \____/ |_| \_\  |_|   |_|      |_|        |______|    |_|
"
}

choose_hash()
{
	echo -e "   Please choose the hashing technique you want to use : \n"
	echo -e "   1. MD5 \n   2. MD4 \n   3. SHA1 \n   4. SHA256 \n   5. SHA384\n   6. SHA512\n"
	read input_hash_type
	echo -e " "
}


enter_hash()
{
	read -p "   Please enter the hash you want to decrypt : " hash 
	echo -e "\n   It might take some time \n"
	website="http://md5decrypt.net/Api/api.php?"
	hash_="hash=$hash"
	email="&email=adityaanand123456789@gmail.com"
	code="&code=66eabfdec82ad497"
}

decrypt()
{	
	choose_hash
	case $input_hash_type in
		1)
			enter_hash
			hash_type="&hash_type=md5"
			parameter=$website$hash_$hash_type$email$code
			echo -e "   The decrypted message for '$hash' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
			;;
		2)
			enter_hash
			hash_type="&hash_type=md4"
			parameter=$website$hash_$hash_type$email$code
			echo -e "   The decrytped message for '$hash' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
			;;
		3)
			enter_hash
			hash_type="&hash_type=sha1"
			parameter=$website$hash_$hash_type$email$code
			echo -e "   The decrytped message for '$hash' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
			;;
		4)
			enter_hash
			hash_type="&hash_type=sha256"
			parameter=$website$hash_$hash_type$email$code
			echo -e "   The decrytped message for '$hash' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
			;;
		5)
			enter_hash
			hash_type="&hash_type=sha384"
			parameter=$website$hash_$hash_type$email$code
			echo -e "   The decrytped message for '$hash' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
			;;
		6)
			enter_hash
			hash_type="&hash_type=sha512"
			parameter=$website$hash_$hash_type$email$code
			echo -e "   The decrytped message for '$hash' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
			;;
		*)
			echo "   Sorry, please try again."
			sleep 5
			clear
			logo
			decrypt
			;;
	esac
}


enter_word()
{
	read -p "   Please enter the word you want to encrypt : " message
	message_encoded=$(python -c "import urllib;r=urllib.pathname2url('$message');print(r)")
	echo -e "\n   It might take some time \n"
	website="http://md5decrypt.net/Api/api.php?"
	word="mot=$message_encoded"
	email="&email=adityaanand123456789@gmail.com"
	code="&code=66eabfdec82ad497"
}

encrypt()
{
	choose_hash
		case $input_hash_type in
			1)
				enter_word
				hash_type="&hash_type=md5"
				parameter=$website$word$hash_type$email$code	
				echo -e "   The encrypted message for '$message' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
				echo -e " "
				;;
			2)
				enter_word
				hash_type="&hash_type=md4"
				parameter=$website$word$hash_type$email$code
				echo -e "   The encrytped message for '$message' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
				echo -e " "
				;;
			3)
				enter_word
				hash_type="&hash_type=sha1"
				parameter=$website$word$hash_type$email$code
				echo -e "   The encrytped message for '$message' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
				echo -e " "
				;;
			4)
				enter_word
				hash_type="&hash_type=sha256"
				parameter=$website$word$hash_type$email$code
				echo -e "   The encrytped message for '$message' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
				echo -e " "
				;;	
			5)
				enter_word
				hash_type="&hash_type=sha384"
				parameter=$website$word$hash_type$email$code
				echo -e "   The encrytped message for '$message' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
				echo -e " "
				;;	
			6)
				enter_word
				hash_type="&hash_type=sha512"
				parameter=$website$word$hash_type$email$code
				echo -e "   The encrytped message for '$message' is : $(python  -c "import urllib2;r=urllib2.Request('$parameter');response=urllib2.urlopen(r);html=response.read();print(html)") \n"
				echo -e " "
				;;	
			*)
				echo "   Sorry, please try again."
				sleep 5
				clear
				logo
				decrypt
				;;
		esac
}


check_hash()
{
	check_num='^[0-9]+$'
	check_alpha='^[A-Za-z]+$'
	check_alnum='^[a-zA-Z0-9]+$'
	
	read -p "   Please enter the hash you want to find out about: " hash
	echo -e "\n   The hashing technique used might be: \n"
	default_size=${#hash}

	first_letter=${word:0:1}
	
	MD5()
	{
    	hs='ae11fd697ec92c7c98de3fac23aba525'
    	hash_size=${#hs}

    	if [[ $hash_size == $default_size ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_num ]] && [[ $hash =~ $check_alnum ]]; then
    		echo -e "    MD5"
    	fi
	}
	MD5

	RC16()
	{
    	hs='4607'
    	hash_size=${#hs}
    	
    	if [[ $hash_size == $default_size ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_num ]]; then
    		echo -e "    RC16"
    	fi
	}
	RC16

	CRC16CCITT()
	{
	    hs='3d08'
	    hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    CRC16CCITT"
	    fi
    }
    CRC16CCITT

	FCS16()
	{
	    hs='0e5b'
	    hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    FCS16"
	    fi
	}
	FCS16

	CRC32()
	{
    	hs='b33fd057'
    	hash_size=${#hs}

    	if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    CRC32"
	    fi
  	}
  	CRC32

	ADLER32()
	{
    	hs='0607cb42'
    	hash_size=${#hs}

    	if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    ADLER32"
	    fi
    }
    ADLER32

	CRC32B()
	{
    	hs='b764a0d9'
    	hash_size=${#hs}

    	if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    CRC32B"
	    fi
    }
    CRC32B

	XOR32()
	{
    	hs='0000003f'
    	hash_size=${#hs}

    	if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    XOR32"
	    fi
    }
    XOR32

	GHash323()
	{
    	hs='80000000'
    	hash_size=${#hs}

    	if [[ $hash_size == $default_size ]] && [[ $hash =~ $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    GHash323"
	    fi
    }
    GHash323

	GHash325()
	{
	    hs='85318985'
	    hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash =~ $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    GHash325"
	    fi
    }
    GHash325

	DESUnix()
	{
    	hs='ZiY8YtDKXJwYQ'
    	hash_size=${#hs}

    	if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]]; then
	    	echo -e "    DESUnix"
	    fi
	}
	DESUnix

	MD5Half()
	{
    	hs='ae11fd697ec92c7c'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MD5Half"
	    fi
    }
    MD5Half

	MD5Middle()
	{
    	hs='7ec92c7c98de3fac'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MD5Middle"
	    fi
    }
    MD5Middle

	MySQL()
	{
    	hs='63cea4673fd25f46'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MySQL"
	    fi
    }
    MySQL

	DomainCachedCredentials()
	{
    	hs='f42005ec1afe77967cbc83dce1b4d714'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    DomainCachedCredentials"
	    fi
    }
    DomainCachedCredentials

	Haval128()
	{
		hs='d6e3ec49aa0f138a619f27609022df10'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval128"
	    fi
    }
    Haval128

	Haval128HMAC()
	{
    	hs='3ce8b0ffd75bc240fc7d967729cd6637'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval128HMAC"
	    fi
    }
    Haval128HMAC

	MD2()
	{
    	hs='08bbef4754d98806c373f2cd7d9a43c4'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MD2"
	    fi
    }
    MD2


	MD2HMAC()
	{
    	hs='4b61b72ead2b0eb0fa3b8a56556a6dca'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MD2HMAC"
	    fi
    }
    MD2HMAC

	MD4()
	{
    	hs='a2acde400e61410e79dacbdfc3413151'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MD4"
	    fi
    }
    MD4

	MD4HMAC()
	{
    	hs='6be20b66f2211fe937294c1c95d1cd4f'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MD4HMAC"
	    fi
    }
    MD4HMAC

	MD5HMAC()
	{
    	hs='d57e43d2c7e397bf788f66541d6fdef9'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MD5HMAC"
	    fi
    }
    MD5HMAC

	MD5HMACWordpress()
	{
    	hs='3f47886719268dfa83468630948228f6'
		hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MD5HMACWordpress"
	    fi
    }
    MD5HMACWordpress

	NTLM()
	{
    	hs='cc348bace876ea440a28ddaeb9fd3550'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    NTLM"
	    fi
    }
    NTLM

	RAdminv2x()
	{
    	hs='baea31c728cbf0cd548476aa687add4b'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    RAdminv2x"
	    fi
    }
    RAdminv2x

	RipeMD128()
	{
    	hs='4985351cd74aff0abc5a75a0c8a54115'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    RipeMD128"
	    fi
    }
    RipeMD128

	RipeMD128HMAC()
	{
    	hs='ae1995b931cf4cbcf1ac6fbf1a83d1d3'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    RipeMD128HMAC"
	    fi
    }
    RipeMD128HMAC

	SNEFRU128()
	{
    	hs='4fb58702b617ac4f7ca87ec77b93da8a'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SNEFRU128"
	    fi
    }
    SNEFRU128

	SNEFRU128HMAC()
    {
    	hs='59b2b9dcc7a9a7d089cecf1b83520350'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SNEFRU128HMAC"
	    fi
    }
    SNEFRU128HMAC
	
	Tiger128()
	{
    	hs='c086184486ec6388ff81ec9f23528727'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Tiger128"
	    fi
    }
    Tiger128

	Tiger128HMAC()
	{
    	hs='c87032009e7c4b2ea27eb6f99723454b'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Tiger128HMAC"
	    fi
    }
    Tiger128HMAC

	md5passsalt()
	{
    	hs='5634cc3b922578434d6e9342ff5913f7'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5passsalt"
	    fi
    }
    md5passsalt

	md5saltmd5pass()
	{
    	hs='245c5763b95ba42d4b02d44bbcd916f1'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5saltmd5pass"
	    fi
    }
    md5saltmd5pass

	md5saltpass()
	{
    	hs='22cc5ce1a1ef747cd3fa06106c148dfa'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5saltpass"
	    fi
    }
    md5saltpass

	md5saltpasssalt()
	{
    	hs='469e9cdcaff745460595a7a386c4db0c'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5saltpasssalt"
	    fi
    }
    md5saltpasssalt

	md5saltpassusername()
	{
    	hs='9ae20f88189f6e3a62711608ddb6f5fd'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5saltpassusername"
	    fi
    }
    md5saltpassusername

	md5saltmd5pass()
	{
    	hs='aca2a052962b2564027ee62933d2382f'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5saltmd5pass"
	    fi
	}
	md5saltmd5pass

	md5saltmd5passsalt()
	{
    	hs='de0237dc03a8efdf6552fbe7788b2fdd'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5saltmd5passsalt"
	    fi
	}
	md5saltmd5passsalt

	md5saltmd5passsalt()
	{
    	hs='5b8b12ca69d3e7b2a3e2308e7bef3e6f'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5saltmd5passsalt"
	    fi
	}
	md5saltmd5passsalt

	md5saltmd5saltpass()
	{
 		hs='d8f3b3f004d387086aae24326b575b23'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5saltmd5saltpass"
	    fi
	}
	md5saltmd5saltpass

	md5saltmd5md5passsalt()
	{    
		hs='81f181454e23319779b03d74d062b1a2'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5saltmd5md5passsalt"
	    fi
	}
	md5saltmd5md5passsalt

	md5username0pass()
	{
    	hs='e44a60f8f2106492ae16581c91edb3ba'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5username0pass"
	    fi
	}
	md5username0pass

	md5usernameLFpass()
	{
    	hs='654741780db415732eaee12b1b909119'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5usernameLFpass"
	    fi
	}
	md5usernameLFpass

	md5usernamemd5passsalt()
	{
    	hs='954ac5505fd1843bbb97d1b2cda0b98f'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5usernamemd5passsalt"
	    fi
	}
	md5usernamemd5passsalt

	md5md5pass()
	{
    	hs='a96103d267d024583d5565436e52dfb3'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5md5pass"
	    fi
	}
	md5md5pass

	md5md5passsalt()
	{
    	hs='5848c73c2482d3c2c7b6af134ed8dd89'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5md5passsalt"
	    fi
	}
	md5md5passsalt

	md5md5passmd5salt()
	{
    	hs='8dc71ef37197b2edba02d48c30217b32'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5md5passmd5salt"
	    fi
	}
	md5md5passmd5salt

	md5md5saltpass()
	{
    	hs='9032fabd905e273b9ceb1e124631bd67'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5md5saltpass"
	    fi
	}
	md5md5saltpass

	md5md5saltmd5pass()
	{
    hs='8966f37dbb4aca377a71a9d3d09cd1ac'
    hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5md5saltmd5pass"
	    fi
	}
	md5md5saltmd5pass

	md5md5usernamepasssalt()
	{
	    hs='4319a3befce729b34c3105dbc29d0c40'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5md5usernamepasssalt"
	    fi
	}
	md5md5usernamepasssalt

	md5md5md5pass()
	{
    	hs='ea086739755920e732d0f4d8c1b6ad8d'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5md5md5pass"
	    fi
	}
	md5md5md5pass

	md5md5md5md5pass()
	{
    	hs='02528c1f2ed8ac7d83fe76f3cf1c133f'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5md5md5pass"
	    fi
	}
	md5md5md5md5pass

	md5md5md5md5md5pass()
	{
    	hs='4548d2c062933dff53928fd4ae427fc0'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5md5md5md5md5pass"
	    fi
	}
	md5md5md5md5md5pass

	md5sha1pass()
	{
    	hs='cb4ebaaedfd536d965c452d9569a6b1e'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5sha1pass"
	    fi
    }
    md5sha1pass

	md5sha1md5pass()
	{
    	hs='099b8a59795e07c334a696a10c0ebce0'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5sha1md5pass"
	    fi
    }
    md5sha1md5pass

	md5sha1md5sha1pass()
	{
    	hs='06e4af76833da7cc138d90602ef80070'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5sha1md5sha1pass"
	    fi
    }
	md5sha1md5sha1pass

	md5strtouppermd5pass()
	{
    	hs='519de146f1a658ab5e5e2aa9b7d2eec8'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    md5strtouppermd5pass"
	    fi
    }
    md5strtouppermd5pass

    LineageIIC4()
    {
    	hs='0x49a57f66bd3d5ba6abda5579c264a0e4' 
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]] && [[ ${hash:0:2}=='0x' ]]; then
	    	echo -e "   LineageIIC4"
	    fi
    }
    LineageIIC4
    
    MD5phpBB3()
    {
    	hs='$H$9kyOtE8CDqMJ44yfn9PFz2E.L2oVzL1'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:0:3}=='$H$' ]]; then
	    	echo -e "   MD5phpBB3"
	    fi
    }
    MD5phpBB3
    
    MD5Unix()
    {
    	hs='$1$cTuJH0Ju$1J8rI.mJReeMvpKUZbSlY/'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:0:3}=='$1$' ]]; then
	    	echo -e "   MD5Unix"
	    fi
    }
    MD5Unix
    
    MD5Wordpress()
    {
    	hs='$P$BiTOhOj3ukMgCci2juN0HRbCdDRqeh.'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:0:3}=='$P$' ]]; then
	    	echo -e "   MD5Wordpress"
	    fi
    }
    MD5Wordpress

    MD5APR()
    {
    	hs='$apr1$qAUKoKlG$3LuCncByN76eLxZAh/Ldr1'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:0:4}=='$apr' ]]; then
	    	echo -e "   MD5APR"
	    fi
    }

    Haval160()
    {
    	hs='a106e921284dd69dad06192a4411ec32fce83dbb'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval160"
	    fi
    }

    Haval160HMAC()
    {
    	hs='29206f83edc1d6c3f680ff11276ec20642881243'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval160HMAC"
	    fi
    }
    
    MySQL5()
    {
    	hs='9bb2fb57063821c762cc009f7584ddae9da431ff'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    MySQL5"
	    fi
    }

    MySQL160bit()
    {
    	hs='*2470c0c06dee42fd1618bb99005adca2ec9d1e19'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:0:1}=='*' ]]; then
	    	echo -e "   MD5phpBB3"
	    fi
    #if len(hash)==len(hs) and hash.isdigit()==False and hash.isalpha()==False and hash.isalnum()==False and hash[0:1].find('*')==0:
    }

	RipeMD160()
	{
    hs='dc65552812c66997ea7320ddfb51f5625d74721b'
    hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    RipeMD160"
	    fi
    }
    RipeMD160

    RipeMD160HMAC()
    {
    	hs='ca28af47653b4f21e96c1235984cb50229331359'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    RipeMD160HMAC"
	    fi
    }
    RipeMD160HMAC

    SHA1()
    {
    	hs='4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA1"
	    fi
    }
    SHA1

    SHA1HMAC()
    {
    	hs='6f5daac3fee96ba1382a09b1ba326ca73dccf9e7'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA1HMAC"
	    fi
    }
    SHA1HMAC

    SHA1MaNGOS()
    {
    	hs='a2c0cdb6d1ebd1b9f85c6e25e0f8732e88f02f96'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA1MaNGOS"
	    fi
    }
    SHA1MaNGOS

    SHA1MaNGOS2()
    {
    	hs='644a29679136e09d0bd99dfd9e8c5be84108b5fd'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA1MaNGOS2"
	    fi
    }
    SHA1MaNGOS2

    Tiger160()
    {
    	hs='c086184486ec6388ff81ec9f235287270429b225'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Tiger160"
	    fi
    }
    Tiger160

    Tiger160HMAC()
    {
    	hs='6603161719da5e56e1866e4f61f79496334e6a10'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Tiger160HMAC"
	    fi
    }
    Tiger160HMAC

    sha1passsalt()
    {
    	hs='f006a1863663c21c541c8d600355abfeeaadb5e4'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1sha1passsalt"
	    fi
    }
    sha1passsalt

    sha1saltpass()
    {
    	hs='299c3d65a0dcab1fc38421783d64d0ecf4113448'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1saltpass"
	    fi
    }
    sha1saltpass
    
    sha1saltmd5pass()
    {
    	hs='860465ede0625deebb4fbbedcb0db9dc65faec30'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1saltmd5pass"
	    fi
    }
    sha1saltmd5pass
    
    sha1saltmd5passsalt()
    {
    	hs='6716d047c98c25a9c2cc54ee6134c73e6315a0ff'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1saltmd5passsalt"
	    fi
    }
    sha1saltmd5passsalt

    sha1saltsha1pass()
    {
    	hs='58714327f9407097c64032a2fd5bff3a260cb85f'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1saltsha1pass"
	    fi
    }
    sha1saltsha1pass

    sha1saltsha1saltsha1pass()
    {
    	hs='cc600a2903130c945aa178396910135cc7f93c63'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1saltsha1saltsha1pass"
	    fi
    }
    sha1saltsha1saltsha1pass
    
    sha1usernamepass()
    {
    	hs='3de3d8093bf04b8eb5f595bc2da3f37358522c9f'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1usernamepass"
	    fi
    }
    sha1usernamepass

    sha1usernamepasssalt()
    {
    	hs='00025111b3c4d0ac1635558ce2393f77e94770c5'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1usernamepasssalt"
	    fi
    }
    sha1usernamepasssalt
    
    sha1md5pass()
    {
    	hs='fa960056c0dea57de94776d3759fb555a15cae87'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1md5pass"
	    fi
    }
    sha1md5pass
    
    sha1md5passsalt()
    {
    	hs='1dad2b71432d83312e61d25aeb627593295bcc9a'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1md5passsalt"
	    fi
    }
    sha1md5passsalt

    sha1md5sha1pass()
    {
    	hs='8bceaeed74c17571c15cdb9494e992db3c263695'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1md5sha1pass"
	    fi
    }
    sha1md5sha1pass

    sha1sha1pass(){
    hs='3109b810188fcde0900f9907d2ebcaa10277d10e'
    hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1sha1pass"
	    fi
    }
    sha1sha1pass

    sha1sha1passsalt()
    {
    	hs='780d43fa11693b61875321b6b54905ee488d7760'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1sha1passsalt"
	    fi
    }
    sha1sha1passsalt
    
    sha1sha1passsubstrpass03()
    {
    	hs='5ed6bc680b59c580db4a38df307bd4621759324e'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1sha1passsubstrpass03"
	    fi
    }
    sha1sha1passsubstrpass03

    sha1sha1saltpass()
    {
    	hs='70506bac605485b4143ca114cbd4a3580d76a413'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1sha1saltpass"
	    fi
    }
    sha1sha1saltpass
    
    sha1sha1sha1pass()
    {
    	hs='3328ee2a3b4bf41805bd6aab8e894a992fa91549'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1sha1sha1pass"
	    fi
    }
    sha1sha1sha1pass

    sha1strtolowerusernamepass()
    {
    	hs='79f575543061e158c2da3799f999eb7c95261f07'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    sha1strtolowerusernamepass"
	    fi
    }
    sha1strtolowerusernamepass

    Haval192()
    {
    	hs='cd3a90a3bebd3fa6b6797eba5dab8441f16a7dfa96c6e641'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval192"
	    fi
    }
    Haval192

    Haval192HMAC()
    {
    	hs='39b4d8ecf70534e2fd86bb04a877d01dbf9387e640366029'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval192HMAC"
	    fi
    }
    Haval192HMAC

    Tiger192()
    {
    	hs='c086184486ec6388ff81ec9f235287270429b2253b248a70'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Tiger192"
	    fi
    }
    Tiger192

    Tiger192HMAC()
    {
    	hs='8e914bb64353d4d29ab680e693272d0bd38023afa3943a41'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Tiger192HMAC"
	    fi
    }
    Tiger192HMAC

    MD5passsaltjoomla1()
    {
    	hs='35d1c0d69a2df62be2df13b087343dc9:BeKMviAfcXeTPTlX'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:32:33}==':' ]]; then
	    	echo -e "   MD5passsaltjoomla1"
	    fi
	}

    SHA1Django()
    {
    	hs='sha1$Zion3R$299c3d65a0dcab1fc38421783d64d0ecf4113448'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:0:5}=='sha1$' ]]; then
	    	echo -e "   SHA1Django"
	    fi
    }

    Haval224()
    {
    	hs='f65d3c0ef6c56f4c74ea884815414c24dbf0195635b550f47eac651a'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval224"
	    fi
    }
    Haval224

    Haval224HMAC()
    {
    	hs='f10de2518a9f7aed5cf09b455112114d18487f0c894e349c3c76a681'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval224HMAC"
	    fi
    }
    Haval224HMAC

    SHA224(){
    hs='e301f414993d5ec2bd1d780688d37fe41512f8b57f6923d054ef8e59'
    hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA224"
	    fi
    }
    SHA224
    
    SHA224HMAC()
    {
    	hs='c15ff86a859892b5e95cdfd50af17d05268824a6c9caaa54e4bf1514'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA224HMAC"
	    fi
    }
    SHA224HMAC

    SHA256()
    {
    	hs='2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA256"
	    fi
    }
    SHA256
    
    SHA256HMAC()
    {
    	hs='d3dd251b7668b8b6c12e639c681e88f2c9b81105ef41caccb25fcde7673a1132'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA256HMAC"
	    fi
    }
    SHA256HMAC

    Haval256()
    {
    	hs='7169ecae19a5cd729f6e9574228b8b3c91699175324e6222dec569d4281d4a4a'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval256"
	    fi
    }
    Haval256

    Haval256HMAC()
    {
    	hs='6aa856a2cfd349fb4ee781749d2d92a1ba2d38866e337a4a1db907654d4d4d7a'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Haval256HMAC"
	    fi
    }
    Haval256HMAC

    GOSTR341194()
    {
    	hs='ab709d384cce5fda0793becd3da0cb6a926c86a8f3460efb471adddee1c63793'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    GOSTR341194"
	    fi
    }
    GOSTR341194

    RipeMD256()
    {
    	hs='5fcbe06df20ce8ee16e92542e591bdea706fbdc2442aecbf42c223f4461a12af'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    RipeMD256"
	    fi
    }
    RipeMD256
    
    RipeMD256HMAC()
    {
    	hs='43227322be1b8d743e004c628e0042184f1288f27c13155412f08beeee0e54bf'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    RipeMD256HMAC"
	    fi
    }
    RipeMD256HMAC

    SNEFRU256()
    {
    	hs='3a654de48e8d6b669258b2d33fe6fb179356083eed6ff67e27c5ebfa4d9732bb'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SNEFRU256"
	    fi
    }
    SNEFRU256

    SNEFRU256HMAC()
    {
    	hs='4e9418436e301a488f675c9508a2d518d8f8f99e966136f2dd7e308b194d74f9'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SNEFRU256HMAC"
	    fi
    }
    SNEFRU256HMAC

    SHA256md5pass()
    {
    	hs='b419557099cfa18a86d1d693e2b3b3e979e7a5aba361d9c4ec585a1a70c7bde4'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA256md5pass"
	    fi
    }
    SHA256md5pass

    SHA256sha1pass()
    {
    	hs='afbed6e0c79338dbfe0000efe6b8e74e3b7121fe73c383ae22f5b505cb39c886'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA256sha1pass"
	    fi
    }
    SHA256sha1pass

    MD5passsaltjoomla2()
    {
    	hs='fb33e01e4f8787dc8beb93dac4107209:fxJUXVjYRafVauT77Cze8XwFrWaeAYB2'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:32:32}==':' ]]; then
	    	echo -e "   MD5passsaltjoomla2"
	    fi
    }
    
    SAM()
    {
    	hs='4318B176C3D8E3DEAAD3B435B51404EE:B7C899154197E8A2A33121D76A240AB5'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:32:33}==':' ]]; then
	    	echo -e "   SAM"
	    fi
    }

    SHA256Django()
    {
    	hs='sha256$Zion3R$9e1a08aa28a22dfff722fad7517bae68a55444bb5e2f909d340767cec9acf2c3'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:0:6}=='sha256' ]]; then
	    	echo -e "   SHA256Django"
	    fi
    }

    RipeMD320()
    {
    	hs='b4f7c8993a389eac4f421b9b3b2bfb3a241d05949324a8dab1286069a18de69aaf5ecc3c2009d8ef'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    RipeMD320"
	    fi
    }
    RipeMD320
    
    RipeMD320HMAC()
    {
    	hs='244516688f8ad7dd625836c0d0bfc3a888854f7c0161f01de81351f61e98807dcd55b39ffe5d7a78'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    RipeMD320HMAC"
	    fi
    }
    RipeMD320HMAC

    SHA384()
    {
    	hs='3b21c44f8d830fa55ee9328a7713c6aad548fe6d7a4a438723a0da67c48c485220081a2fbc3e8c17fd9bd65f8d4b4e6b'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA384"
	    fi
    }
    SHA384
    
    SHA384HMAC()
    {
    	hs='bef0dd791e814d28b4115eb6924a10beb53da47d463171fe8e63f68207521a4171219bb91d0580bca37b0f96fddeeb8b'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA384HMAC"
	    fi
    }
    SHA384HMAC

    SHA256s()
    {
    	hs='$6$g4TpUQzk$OmsZBJFwvy6MwZckPvVYfDnwsgktm2CckOlNJGy9HNwHSuHFvywGIuwkJ6Bjn3kKbB6zoyEjIYNMpHWBNxJ6g.'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:0:3}=='$6$' ]]; then
	    	echo -e "    SHA256s"
	    fi
	}
	SHA256s

    SHA384Django()
    {
    	hs='sha384$Zion3R$88cfd5bc332a4af9f09aa33a1593f24eddc01de00b84395765193c3887f4deac46dc723ac14ddeb4d3a9b958816b7bba'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash != $check_alnum ]] && [[ ${hash:0:6}=='sha384' ]]; then
	    	echo -e "   SHA384Django"
	    fi
    }
    SHA384Django

    SHA512()
    {
    	hs='ea8e6f0935b34e2e6573b89c0856c81b831ef2cadfdee9f44eb9aa0955155ba5e8dd97f85c73f030666846773c91404fb0e12fb38936c56f8cf38a33ac89a24e'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA512"
	    fi
    }
    SHA512

    SHA512HMAC()
    {
    	hs='dd0ada8693250b31d9f44f3ec2d4a106003a6ce67eaa92e384b356d1b4ef6d66a818d47c1f3a2c6e8a9a9b9bdbd28d485e06161ccd0f528c8bbb5541c3fef36f'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    SHA512HMAC"
	    fi
    }
    SHA512HMAC

    Whirlpool()
    {
    	hs='76df96157e632410998ad7f823d82930f79a96578acc8ac5ce1bfc34346cf64b4610aefa8a549da3f0c1da36dad314927cebf8ca6f3fcd0649d363c5a370dddb'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    Whirlpool"
	    fi
    }
    Whirlpool

    WhirlpoolHMAC()
    {
    	hs='77996016cf6111e97d6ad31484bab1bf7de7b7ee64aebbc243e650a75a2f9256cef104e504d3cf29405888fca5a231fcac85d36cd614b1d52fce850b53ddf7f9'
    	hash_size=${#hs}

	    if [[ $hash_size == $default_size ]] && [[ $hash != $check_num ]] && [[ $hash != $check_alpha ]] && [[ $hash =~ $check_alnum ]]; then
	    	echo -e "    WhirlpoolHMAC"
	    fi
    }
    WhirlpoolHMAC
}

main()
{
	echo -e "   Choose any one option from below:\n"
	echo -e "   1. Decrypt the message \n"
	echo -e "   2. Encrypt the message \n"
	echo -e "   3. Identify the hash \n"

	read input_crypt_type
	echo -e " "
	case $input_crypt_type in
		1)
			decrypt	
			;;
		2)  
			encrypt
			;;
		3)
			check_hash
			echo -e ""
			;;
		*)
			echo "   Sorry, please try again."
			sleep 0
			clear
			logo
			main
			;;
	esac
}

clear

logo

main