#!/bin/bash

total_found=0

score_report="/home/bezos/Desktop/ScoreReport.html"
tail xxzz.txt
total_found=`cat xxzz.txt`
function update-found
{
	#updates vuln found counts in score report
	
        sed -i "s/id=\"total_found\".*/id=\"total_found\">$total_found\/58<\/center><\/h3>/g" $score_report

	echo $total_found > xxzz.txt
}

function show-vuln()
{
	#allows vuln name to be seen in score report
	sed -i "s/id=\"$1\"style=\"display:none\"/id=\"$1\"style=\"display:block\"/g" $score_report
	((total_found+=$4))
	#replaces placeholder name with actual vuln name (obfuscation)
	sed -i "s/$2/$3/g" $score_report
	notify-send "Congrats!" "You Gained Points"
	update-found
}

function hide-vuln()
{
	#hides vuln name from score report
	sed -i "s/id=\"$1\"style=\"display:block\"/id=\"$1\"style=\"display:none\"/g" $score_report
	((total_found-=$4))
	#replaces placeholder name (people should keep their own notes on the points they've gained)
	sed -i "s/$2/$3/g" $score_report
	notify-send "Uh Oh!" "You Lost Points"
	update-found
}

function penalty()
{
	sed -i "s/id=\"$1\"style=\"display:none\"/id=\"$1\"style=\"display:block\"/g" $score_report
	((total_found-=$4))
        #replaces placeholder name (people should keep their own notes on the points they've gained)
        sed -i "s/$2/$3/g" $score_report
        notify-send "Uh Oh!" "You Lost Points"
        update-found

}

function notify-send()
{
    #Detect the name of the display in use
    local display=":$(ls /tmp/.X11-unix/* | sed 's#/tmp/.X11-unix/X##' | head -n 1)"

    #Detect the user using such display
    local user=$(who | grep '('$display')' | awk '{print $1}' | head -n 1)

    #Detect the id of the user
    local uid=$(id -u $user)

    sudo -u $user DISPLAY=$display DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus notify-send "$@"
}

update-found

while true
do
	if ( ! cat /etc/apache2/ports.conf | grep -v 443 | grep Listen ); then
		if ( cat $score_report | grep 'id="1"' | grep "display:none" ); then
			show-vuln '1' "Vuln1;" "Apache runs on correct port" 2
		fi
	elif ( cat $score_report | grep 'id="1"' | grep "display:block" ); then
		hide-vuln '1' "Apache runs on correct port" "Vuln1;" 2
	fi

	if ( cat /etc/apache2/conf-enabled/security.conf | grep "ServerTokens" | grep -iF "prod" ); then
		if ( cat $score_report | grep 'id="2"' | grep "display:none" ); then
			show-vuln '2' "Vuln2;" "ServerTokens set to prod" 3
		fi
	elif ( cat $score_report | grep 'id="2"' | grep "display:block" ); then
		hide-vuln '2' "ServerTokens set to prod" "Vuln2;" 3
	fi

	if ( cat /etc/apache2/conf-enabled/security.conf | grep "TraceEnable" | grep -iF "off" ); then
		if ( cat $score_report | grep 'id="3"' | grep "display:none" ); then
			show-vuln '3' "Vuln3;" "TraceEnable set to off" 3
		fi
	elif ( cat $score_report | grep 'id="3"' | grep "display:block" ); then
		hide-vuln '3' "TraceEnable set to off" "Vuln3;" 3
	fi
	
	if ( cat /etc/apache2/conf-enabled/security.conf | grep -iF "header" | grep "X-XSS-Protection" ); then
		if ( cat $score_report | grep 'id="4"' | grep "display:none" ); then
			show-vuln '4' "Vuln4;" "XSS protection enabled" 10
		fi
	elif ( cat $score_report | grep 'id="4"' |  grep "display:block" ); then
		hide-vuln '4' "XSS protection enabled" "Vuln4;" 10
	fi

	if ( cat /etc/sysctl.conf | grep "ipv4" | grep "icmp_echo_ignore_all" | grep "0" ); then
		if ( cat $score_report | grep 'id="5"' | grep "display:none" ); then
			show-vuln '5' "Vuln5;" "ICMP pings enabled" 1
		fi
	elif ( cat $score_report | grep 'id="5"' | grep "display:block" ); then
		hide-vuln '5' "ICMP pings enabled" "Vuln5;" 1
	fi

	if ( cat /etc/apache2/apache2.conf | grep -A 10 "/var/www" | grep -iF "options" | grep "none" || cat /etc/apache2/apache2.conf | grep -A 10 "/var/www" | grep -iF "options" | grep -iF "\-index" ); then
		if ( cat $score_report | grep 'id="6"' | grep "display:none" ); then
			show-vuln '6' "Vuln6;" "Indexing disabled" 5
		fi
	elif ( cat $score_report | grep 'id="6"' | grep "display:block" ); then
		hide-vuln '6' "Indexing disabled" "Vuln6;" 5
	fi

	if ( ! ls -al /var/www/html | grep "\.\.\." ); then
		if ( cat $score_report | grep 'id="7"' | grep "display:none" ); then
			show-vuln '7' "Vuln7;" 'Symbolic link to / removed' 5
		fi
	elif ( cat $score_report | grep 'id="7"' | grep "display:block" ); then
		hide-vuln '7' 'Symbolic link to / removed' "Vuln7;" 5
	fi

	if ( ! dpkg -l | grep "netcat" ); then
                if ( cat $score_report | grep 'id="8"' | grep "display:none" ); then
                        show-vuln '8' "Vuln8;" "Netcat is removed" 1
                fi
        elif ( cat $score_report | grep 'id="8"' | grep "display:block" ); then
                hide-vuln '8' "Netcat is removed" "Vuln8;" 1
        fi

	if ( ! dpkg -l | grep "samba" | grep -v "python" ); then
                if ( cat $score_report | grep 'id="9"' | grep "display:none" ); then
                        show-vuln '9' "Vuln9;" "Samba is removed" 1
                fi
        elif ( cat $score_report | grep 'id="9"' | grep "display:block" ); then
                hide-vuln '9' "Samba is removed" "Vuln9;" 1
        fi

	if ( ! cat /etc/passwd | grep "chale" ); then
		if ( cat $score_report | grep 'id="10"' | grep "display:none" ); then
                        show-vuln '10' "Vuln10;" "Unauthorized user chale is removed" 1
                fi
        elif ( cat $score_report | grep 'id="10"' | grep "display:block" ); then
                hide-vuln '10' "Unauthorized user chale is removed" "Vuln10;" 1
        fi

	if ( ls -al /etc/shadow | grep ^"-rw-------" || ls -al /etc/shadow | grep ^"-rw-r-----" ); then
                if ( cat $score_report | grep 'id="11"' | grep "display:none" ); then
                        show-vuln '11' "Vuln11;" "Correct permissions set on /etc/shadow" 3
                fi
        elif ( cat $score_report | grep 'id="11"' | grep "display:block" ); then
                hide-vuln '11' "Correct permissions set on /etc/shadow" "Vuln11;" 3
        fi

	if ( ls -al /var | grep tmp | grep rwt  ); then
                if ( cat $score_report | grep 'id="12"' | grep "display:none" ); then
                        show-vuln '12' "Vuln12;" "Stickybit set on /var/tmp" 3
                fi
        elif ( cat $score_report | grep 'id="12"' | grep "display:block" ); then
                hide-vuln '12' "Stickybit set on /var/tmp" "Vuln12;" 3
        fi

	if ( ls -o /etc | grep "fstab" | grep "root" ); then
                if ( cat $score_report | grep 'id="13"' | grep "display:none" ); then
                        show-vuln '13' "Vuln13;" "Correct owner on /etc/fstab" 5
                fi
        elif ( cat $score_report | grep 'id="13"' | grep "display:block" ); then
                hide-vuln '13' "Correct owner of /etc/fstab" "Vuln13;" 5
        fi

	if ( cat /home/bezos/Desktop/Forensics/Forensics1 | grep "5560" ); then
                if ( cat $score_report | grep 'id="14"' | grep "display:none" ); then
                        show-vuln '14' "Vuln14;" "Forensics1 correct" 5
                fi
        elif ( cat $score_report | grep 'id="14"' | grep "display:block" ); then
                hide-vuln '14' "Forensics1 correct" "Vuln14;" 5
        fi

	if ( cat /home/bezos/Desktop/Forensics/Forensics2 | grep -iF "Vladdy daddy is mean" ); then
                if ( cat $score_report | grep 'id="15"' | grep "display:none" ); then
                        show-vuln '15' "Vuln15;" "Forensics2 correct" 5
                fi
        elif ( cat $score_report | grep 'id="15"' | grep "display:block" ); then
                hide-vuln '15' "Forensics2 correct" "Vuln15;" 5
        fi

	if ( cat /home/bezos/Desktop/Forensics/Forensics3 | grep -iF "an introduction to computer science for young people" ); then
                if ( cat $score_report | grep 'id="16"' | grep "display:none" ); then
                        show-vuln '16' "Vuln16;" "Forensics3 correct" 5
                fi
        elif ( cat $score_report | grep 'id="16"' | grep "display:block" ); then
                hide-vuln '16' "Forensics3 correct" "Vuln16;" 5
        fi

	if ( ! service apache2 status | grep active ); then
                if ( cat $score_report | grep 'id="17"' | grep "display:none" ); then
                        penalty '17' "Vuln17;" "PENALTY: Service Apache2 is not running" 50
                fi
        elif ( cat $score_report | grep 'id="17"' | grep "display:block" ); then
                show-vuln '17' "PENALTY: Service Apache2 is not running" "Vuln17;" 50
        fi

sleep 10
done
