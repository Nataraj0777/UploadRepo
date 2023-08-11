#! /bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

fw_file="$CERBERUS_FW"
opts="$CERBERUS_OPTS"
if [ -z "$UTILITY_DIR" ]; then
	UTILITY_DIR="."
fi
if [ -z "$SEAL_SCRIPT_PATH" ]; then
	SEAL_SCRIPT_PATH="$CERBERUS_ROOT/cerberus/tools/testing"
fi
if [ -z "$TCGLOG_SCRIPT_PATH" ]; then
	TCGLOG_SCRIPT_PATH="$CERBERUS_ROOT/cerberus/tools/testing"
fi
if [ -n "$BMC_IP" ]; then
	utility="$UTILITY_DIR/cerberus_utility -h $BMC_IP -u admin -p admin -r 0 $opts"
else
	utility="$UTILITY_DIR/cerberus_utility -r 0 $opts"
fi
seal_script="$SEAL_SCRIPT_PATH/seal_data.sh"
tcg_script="$TCGLOG_SCRIPT_PATH/tcg_log_test.py"
if [ -n "$EXT_OPENSSL" ]; then
	export LD_LIBRARY_PATH="/opt/openssl-1.1.1d/lib"
	openssl="/opt/openssl-1.1.1d/bin/openssl"
else
	openssl="openssl"
fi

count=0
error=0
verbose=0
fatal=1
once=0
version=0
certs=0
ftpm=0
aux_certs=0
unsealrsa=
unsealecc=
unsealeccsha=
seed_len=
unsealretrycnt=1
debuglog=0
tcglog=0
tcglogverify=1
heap=0
update=0
soc=0
socreset=0
socgpio=0

for opt in $@; do
	case $opt in
		verbose,*)
			verbose=`echo $opt | awk -F , '{print $2}'`
			;;

		loop,*)
			count=`echo $opt | awk -F , '{print $2}'`
			;;

		count)
			fatal=0
			;;

		once)
			once=1
			;;

		version)
			version=1
			;;

		no-version)
			version=0
			;;

		certs)
			certs=1
			aux_certs=1
			;;

		no-certs)
			certs=0
			;;

		no-aux-certs)
			aux_certs=0
			unsealrsa=0
			;;

		ftpm)
			ftpm=1
			;;

		no-ftpm)
			ftpm=0
			;;

		unseal)
			unsealrsa=0
			unsealecc=1
			unsealeccsha=2
			;;

		no-unseal)
			unsealrsa=
			unsealecc=
			unsealeccsha=
			;;

		unseal-rsa)
			unsealrsa=0
			;;

		no-unseal-rsa)
			unsealrsa=
			;;

		unseal-ecdh)
			unsealecc=1
			;;

		no-unseal-ecdh)
			unseal-ecc=
			;;

		unseal-ecdh-sha)
			unsealeccsha=2
			;;

		no-unseal-ecdh_sha)
			unsealeccsha=
			;;

		seed-len,*)
			seed_len=`echo $opt | awk -F , '{print $2}'`
			;;

		unseal-retry-cnt,*)
			unsealretrycnt=`echo $opt | awk -F , '{print $2}'`
			;;

		debuglog)
			debuglog=1
			;;

		no-debuglog)
			debuglog=0
			;;

		tcglog)
			tcglog=1
			;;

		no-tcglog)
			tcglog=0
			;;

		no-tcglogverify)
			tcglogverify=0
			;;

		heap)
			heap=1
			;;

		no-heap)
			heap=0
			;;

		soc)
			soc=1
			;;

		no-soc)
			soc=0
			;;

		update)
			update=1
			;;

		no-update)
			update=0
			;;

		socgpio)
			socgpio=1
			;;

		no-socgpio)
			socgpio=0
			;;

		socreset)
			socreset=1
			;;

		reboot)
			socreset=2
			;;

		no-socreset)
			socreset=0
			;;

		all)
			version=1
			certs=1
			aux_certs=1
			unsealrsa=0
			unsealecc=1
			unsealeccsha=2
			debuglog=1
			tcglog=1
			heap=1
			update=1
			;;
	esac
done

if [ $unsealretrycnt -eq 0 ]; then
	unsealretrycnt=1
fi


if [ $certs -eq 1 ] || [ -n "$unsealrsa" ] || [ -n "$unsealecc" ] || [ -n "$unsealeccsha" ]; then
	digests=`$utility getdigests 0`
	if [ $? -ne 0 ]; then
		echo "$digests"
		exit 1
	fi

	echo $digests | grep -q "Digest (3)"
	if [ $? -ne 0 ]; then
		cert_num=1
	else
		cert_num=3
	fi

	echo "Attestation cert is index: $cert_num"
fi

caps=`$utility devicecaps`
if [ $? -ne 0 ]; then
	echo "$caps"
	exit 1
fi

max_msg=`echo "$caps" | grep "Max Message Body" | awk '{print $4}'`
echo "Device max message size: $max_msg"

if [ $socgpio -eq 1 ]; then
	# Set output GPIO
	echo out > /sys/class/gpio/gpio347/direction

	# Give SPI to Cerberus
	echo 0 > /sys/class/gpio/gpio347/value
fi

cmd_error() {
	echo "$out"
	let 'error = error + 1'
	if [ $fatal -eq 1 ]; then
		exit 1
	fi
}

cmd_output() {
	if [ $verbose -ge $1 ]; then
		echo "$out"
		echo ""
	fi
}

execute_cmd() {
	if [ $verbose -ge $2 ]; then
		echo "$1"
	fi

	out=`$1`
	if [ $? -ne 0 ]; then
		return 1
	fi

	cmd_output $2
}

cmd_certs() {
	echo ""
	echo "Verify device certificates"
	rm slot*.der*

	execute_cmd "$utility getdigests 0" 1
	if [ $? -ne 0 ]; then
		return 1
	fi

	execute_cmd "$utility getcertchain 0 slot0" 1
	if [ $? -ne 0 ]; then
		return 1
	fi

	if [ $aux_certs -eq 1 ]; then
		execute_cmd "$utility getdigests 1" 1
		if [ $? -ne 0 ]; then
			return 1
		fi

		execute_cmd "$utility getcertchain 1 slot1" 1
		if [ $? -ne 0 ]; then
			return 1
		fi
	fi

	out=`find . -maxdepth 1 -iname 'slot[0|1]*der' -exec openssl x509 -inform DER -outform PEM -in {} -out {}.pem \;`
	if [ $? -ne 0 ]; then
		return 1
	fi

	if [ $cert_num -eq 1 ]; then
		execute_cmd "openssl verify -CAfile slot0_0.der.pem slot0_1.der.pem" 1
		if [ $? -ne 0 ]; then
			return 1
		fi

		if [ $aux_certs -eq 1 ]; then
			execute_cmd "openssl verify -CAfile slot1_0.der.pem slot1_1.der.pem" 1
			if [ $? -ne 0 ]; then
				return 1
			fi
		fi
	else
		execute_cmd "$openssl verify -CAfile slot0_0.der.pem -untrusted slot0_1.der.pem -untrusted slot0_2.der.pem slot0_3.der.pem" 1
		if [ $? -ne 0 ]; then
			return 1
		fi

		if [ $aux_certs -eq 1 ]; then
			execute_cmd "$openssl verify -CAfile slot1_0.der.pem -untrusted slot1_1.der.pem -untrusted slot1_2.der.pem slot1_3.der.pem" 1
			if [ $? -ne 0 ]; then
				return 1
			fi
		fi
	fi
}

cmd_tcglog() {
	execute_cmd "$utility tcglogread" 1
	if [ $? -ne 0 ]; then
		return 1
	fi

	if [ $tcglogverify -ne 0 ]; then
		pmr0_entry=`echo "$out" | grep -En '\| 0 ' | cut -d: -f 1 | tail -n 1`
		if [ -n "$pmr0_entry" ]; then
			pmr0=`echo "$out" | tail -n +$pmr0_entry | head -n 1 | awk '{print tolower($NF)}'`
		else
			pmr0=
		fi

		pmr1_entry=`echo "$out" | grep -En '\| 1 ' | cut -d: -f 1 | tail -n 1`
		if [ -n "$pmr1_entry" ]; then
			pmr1=`echo "$out" | tail -n +$pmr1_entry | head -n 1 | awk '{print tolower($NF)}'`
		else
			pmr1=
		fi

		pmr2_entry=`echo "$out" | grep -En '\| 2 ' | cut -d: -f 1 | tail -n 1`
		if [ -n "$pmr2_entry" ]; then
			pmr2=`echo "$out" | tail -n +$pmr2_entry | head -n 1 | awk '{print tolower($NF)}'`
		else
			pmr2=
		fi

		pmr3_entry=`echo "$out" | grep -En '\| 3 ' | cut -d: -f 1 | tail -n 1`
		if [ -n "$pmr3_entry" ]; then
			pmr3=`echo "$out" | tail -n +$pmr3_entry | head -n 1 | awk '{print tolower($NF)}'`
		else
			pmr3=
		fi

		pmr4_entry=`echo "$out" | grep -En '\| 4 ' | cut -d: -f 1 | tail -n 1`
		if [ -n "$pmr4_entry" ]; then
			pmr4=`echo "$out" | tail -n +$pmr4_entry | head -n 1 | awk '{print tolower($NF)}'`
		else
			pmr4=
		fi
	else
		pmr0=
		pmr1=
		pmr2=
		pmr3=
		pmr4=
	fi
}

cmd_unseal() {
	echo ""
	let 'cipher_len = max_msg - 365'
	case $i in
		0)
			seal_params="0 2"
			let 'cipher_len = cipher_len - 384'
			echo "RSA Unseal"
			;;
		1)
			seal_params="1 0"
			let 'cipher_len = -cipher_len'
			echo "ECDH Unseal"
			;;
		2)
			seal_params="1 1"
			let 'cipher_len = -cipher_len'
			echo "ECDH+SHA256 Unseal"
			;;
	esac

	if [ $i -eq 0 ]; then
		execute_cmd "$utility getcert 1 $cert_num cert.der" 1
	else
		execute_cmd "$utility getcert 0 $cert_num cert.der" 1
	fi
	if [ $? -ne 0 ]; then
		return 1
	fi

	cmd_tcglog
	if [ $? -ne 0 ]; then
		return 1
	fi

	echo "Sealing: $seal_params"

	unseal_cmd="$utility unseal $seal_params seed.bin cipher.bin sealing.bin hmac.bin"
	seal_cmd="$seal_script $seal_params cert.der"

	sealing=`PMR0="$pmr0" PMR1="$pmr1" PMR2="$pmr2" PMR3="$pmr3" PMR4="$pmr4" CIPHER_LEN="$cipher_len" SEED_LEN="$seed_len" $seal_cmd 2>&1`
	if [ $? -ne 0 ]; then
		out="$sealing"
		return 1
	fi

	key=`echo "$sealing" | grep stdin | awk '{print $2}'`
	echo "$sealing"
	echo "Sealed Key: $key"
	echo ""

	retry=0
	while [ $retry -lt $unsealretrycnt ]; do
		unsealing=`$unseal_cmd 2>&1`
		if [ $? -ne 0 ]; then
			let 'retry = retry + 1'
			if [ $retry -ge $unsealretrycnt ]; then
				out="$unsealing"
				return 1
			else
				echo "$unsealing"
			fi
		else
			break
		fi
	done

	line=`echo "$unsealing" | grep -n "Encryption key length" | cut -d: -f 1`
	let 'line = line + 1'
	out=`echo "$unsealing" | tail -n +$line | head -n 1 | sed 's/ //g' | awk '{print tolower($0)}'`
	echo "$unsealing"
	echo "Unsealed Key: $out"

	out=`diff <(echo "$key") <(echo "$out")`
	if [ $? -ne 0 ]; then
		return 1
	fi
}

cmd_tcgexport() {
	execute_cmd "$utility tcglogexport tcg.log" 1
	if [ $? -ne 0 ]; then
		return 1
	fi

	if [ $tcglogverify -ne 0 ]; then
		execute_cmd "$tcg_script tcg.log" 1

		parsed="$out"
		line=`echo "$parsed" | grep -n "PCR Measurements" | cut -d: -f 1`

		let 'line = line + 1'
		if [ -n "$pmr0" ]; then
			check_pmr0=`echo "$parsed" | tail -n +$line | head -n 1 | cut -d: -f 2`
			out=`diff <(echo "$pmr0") <(echo "$check_pmr0")`
			if [ $? -ne 0 ]; then
				echo "PMR0:"
				return 1
			fi
		fi

		let 'line = line + 1'
		if [ -n "$pmr1" ]; then
			check_pmr1=`echo "$parsed" | tail -n +$line | head -n 1 | cut -d: -f 2`
			out=`diff <(echo "$pmr1") <(echo "$check_pmr1")`
			if [ $? -ne 0 ]; then
				echo "PMR1:"
				return 1
			fi
		fi

		let 'line = line + 1'
		if [ -n "$pmr2" ]; then
			check_pmr2=`echo "$parsed" | tail -n +$line | head -n 1 | cut -d: -f 2`
			out=`diff <(echo "$pmr2") <(echo "$check_pmr2")`
			if [ $? -ne 0 ]; then
				echo "PMR2:"
				return 1
			fi
		fi

		let 'line = line + 1'
		if [ -n "$pmr3" ]; then
			check_pmr3=`echo "$parsed" | tail -n +$line | head -n 1 | cut -d: -f 2`
			out=`diff <(echo "$pmr3") <(echo "$check_pmr3")`
			if [ $? -ne 0 ]; then
				echo "PMR3:"
				return 1
			fi
		fi

		let 'line = line + 1'
		if [ -n "$pmr4" ]; then
			check_pmr4=`echo "$parsed" | tail -n +$line | head -n 1 | cut -d: -f 2`
			out=`diff <(echo "$pmr4") <(echo "$check_pmr4")`
			if [ $? -ne 0 ]; then
				echo "PMR4:"
				return 1
			fi
		fi
	fi
}

cmd_log() {
	if [ $1 -eq 1 ]; then
		echo ""
		echo "Reading Debug Log"
		execute_cmd "$utility debuglogread" 2
		if [ $? -ne 0 ]; then
			cmd_error
		fi
	fi

	if [ $2 -eq 1 ]; then
		echo ""
		echo "Reading TCG Log"
		cmd_tcglog
		if [ $? -ne 0 ]; then
			cmd_error
		else
			cmd_tcgexport
			if [ $? -ne 0 ]; then
				cmd_error
			fi
		fi
	fi
}

cmd_soc() {
	echo ""
	echo "SoC Read Commands"

	execute_cmd "$utility socgetbootmode" 0
	if [ $? -ne 0 ]; then
		cmd_error
	fi

	execute_cmd "$utility socgetmacid" 0
	if [ $? -ne 0 ]; then
		cmd_error
	fi

	execute_cmd "$utility socgetdebuglevel" 0
	if [ $? -ne 0 ]; then
		cmd_error
	fi
}

cmd_soc_fw_verify() {
	echo ""
	echo "Trigger Verification of SoC FW"

	# Take SPI from Cerberus
	echo 1 > /sys/class/gpio/gpio347/value

	# Give SPI to Cerberus
	echo 0 > /sys/class/gpio/gpio347/value

	start=`date -u +%s`
	let 'end = start + 6'

	# Wait for verification to run, but query for certs while it does
	while [ $start -lt $end ]; do
		execute_cmd "$utility getcertchain 0 slot0" 2
		if [ $? -ne 0 ]; then
			cmd_error
		fi

		if [ $aux_certs -eq 1 ]; then
			execute_cmd "$utility getcertchain 1 slot1" 2
			if [ $? -ne 0 ]; then
				cmd_error
			fi
		fi

		start=`date -u +%s`
	done
}

cmd_update() {
	echo ""
	echo "Starting FW update"
	execute_cmd "$utility fwupdate $fw_file" 1
	if [ $? -ne 0 ]; then
		cmd_error
	fi

	sleep 20
}


while (true); do
	let 'count = count + 1'
	echo "++++++++++++++++"
	echo "Loop: $count"
	if [ $fatal -eq 0 ]; then
		echo "Errors: $error"
	fi
	echo "++++++++++++++++"

	if [ $version -eq 1 ]; then
		execute_cmd "$utility fwversion" 0
		if [ $? -ne 0 ]; then
			cmd_error
		fi

		execute_cmd "$utility getresetcounter 0 0" 0
		if [ $? -ne 0 ]; then
			cmd_error
		fi
	fi

	if [ $certs -eq 1 ]; then
		cmd_certs
		if [ $? -ne 0 ]; then
			cmd_error
		fi
	fi

	if [ $ftpm -eq 1 ]; then
		execute_cmd "/usr/bin/tests/LinuxTpmUtil all" 0
		if [ $? -ne 0 ]; then
			cmd_error
		fi
	fi

	for i in $unsealrsa $unsealecc $unsealeccsha; do
		cmd_unseal
		if [ $? -ne 0 ]; then
			cmd_error
		fi
	done

	if [ $debuglog -eq 1 ] || [ $tcglog -eq 1 ]; then
		cmd_log $debuglog $tcglog
	fi

	if [ $soc -eq 1 ]; then
		cmd_soc
	fi

	if [ $socgpio -eq 1 ]; then
		cmd_soc_fw_verify
	fi

	if [ $heap -eq 1 ]; then
		execute_cmd "$utility diagheap" 0
		if [ $? -ne 0 ]; then
			cmd_error
		fi
	fi

	if [ $update -eq 1 ]; then
		cmd_update
	fi

	if [ $socreset -eq 1 ]; then
		execute_cmd "$utility socreset" 0
		if [ $? -ne 0 ]; then
			cmd_error
		fi
	elif [ $socreset -eq 2 ]; then
		reboot
		# Script should be terminated by the system at this point.
	fi

	if [ $once -eq 1 ]; then
		exit 0
	fi
done
