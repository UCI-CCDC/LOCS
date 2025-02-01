#!/bin/sh
hostname || cat /etc/hostname || hostnamectl hostname
