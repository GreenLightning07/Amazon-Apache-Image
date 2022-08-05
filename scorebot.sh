#!/bin/bash

total_found=0

score_report="/home/cyber/Desktop/ScoreReport.html"

function update-found
{
	#updates vuln found counts in score report
	
        sed -i "s/id=\"total_found\".*/id=\"total_found\">$total_found\/200<\/center><\/h3>/g" $score_report
        sed -i "s/id=\"linux_found\".*/id=\"linux_found\">LINUX ($linux_found\/30)<\/button>/g" $score_report

	echo $total_found
}

function show-vuln()
{
	#allows vuln name to be seen in score report
	sed -i "s/id=\"$1\"style=\"display:none\"/id=\"$1\"style=\"display:block\"/g" $score_report
	((total_found++))
	#replaces placeholder name with actual vuln name (obfuscation)
	sed -i "s/$2/$3/g" $score_report
	notify-send "Congrats!" "You Gained Points"
	update-found
}

function hide-vuln()
{
	#hides vuln name from score report
	sed -i "s/id=\"$1\"style=\"display:block\"/id=\"$1\"style=\"display:none\"/g" $score_report
	((total-found--))
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
