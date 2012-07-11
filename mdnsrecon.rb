#!/usr/bin/env ruby
require 'open3'
require 'fileutils'
require 'getoptlong'
require 'csv'

# Functions for printing messages Metasploit style
#---------------------------------------------------------------------

def print_error(text)
	if STDOUT.tty?
		puts "\e[31m[!]\e[0m #{text}"
	else
		puts "[!] #{text}"
	end
end

def print_good(text)
	if STDOUT.tty?
		puts "\e[32m[*]\e[0m #{text}"
	else
		puts "[*] #{text}"
	end
end

def print_status(text)
	if STDOUT.tty?
		puts "\e[34m[-]\e[0m #{text}"
	else
		puts "[-] #{text}"
	end
end

#---------------------------------------------------------------------

# Function to check if running as root
def check_root
	# Make sure we are running as root
	print_status("Checking if running as root")
	if Process.uid != 0
		print_error("You are not running as Root!")
		exit
	end
	# Make sure we are running in Linux
	if not RUBY_PLATFORM =~ /linux/
		print_error("This script only works in linux")
		exit
	end
end

# Function to check is the service is running
def check_avahi
	if File.exists?("/etc/debian_version")
		stdin,stdout,stderr = Open3.popen3("/usr/bin/lsb_release -d")
		if stdout.read.chomp =~ /ubuntu/i
			stdin,stdout,stderr = Open3.popen3("/usr/bin/service avahi-daemon status")
			if stdout.read.chomp =~ /stop/i
				print_error("Avahi Service is not running will attempt to start it")
				check_root
				stdin,stdout,stderr = Open3.popen3("/usr/bin/service avahi-daemon start")
				if stdout.read.chomp =~ /running/i
					print_good("Avahi service successfuly startered")
				else
					print_error("Could not start Avahi service")
					exit
				end
			end
		else
			stdin,stdout,stderr = Open3.popen3("/etc/init.d/avahi-daemon status")
			if stdout.read.chomp =~ /not/i
				print_error("Avahi Service is not running will attempt to start it")
				check_root
				Open3.popen3("/usr/bin/service avahi-daemon start")
				sleep 2.0
				stdin,stdout,stderr = Open3.popen3("/etc/init.d/avahi-daemon status")
				if stdout.read.chomp =~ /running/i
					print_good("Avahi service successfuly startered")
				else
					print_error("Could not start Avahi service")
					exit
				end
			end
		end
	end
end

# Function to check if the avahi-utils are installed
def check_utils
	if not File.exists?("/usr/bin/avahi-browse")
		print_error("Avahi Utils are not installed: run `apt-get install avahi-utils` to install them.")
		exit
	end
end

# Function to get the MDNS Records
def get_records
	stdin,stdout,stderr = Open3.popen3("/usr/bin/avahi-browse -a -r -t -p")
	found = []
	stdout.each_line do |l|
		if l =~ /^=/
			elements = l.split(";")
			record = { 
				:service => elements[4],
				:domain => elements[5],
				:host => elements[6],
				:ip => elements[7],
				:port => elements[8],
				:txt => "\'#{elements[9].chomp}\'"
				}
			found << record
		end
	end
	return found
end

# Function for printing the records found
def print_records(records)
	print_status("Records found:")
	records.each do |r|
		print_good("\tHost: #{r[:host]}")
		print_good("\tIP: #{r[:ip]}")
		print_good("\tPort: #{r[:port]}")
		print_good("\tService:#{r[:service]}")
		print_good("\tText:#{r[:txt]}")
		print_good("")
	end
end

# Function for printing the records in grepable format
def print_grep(records)
	records.each do |r|
		puts r.values.join("\\")
	end
end

def gen_csv(csvfile, records)
	headers = records[0].keys
	CSV.open(csvfile, "wb") do |csv|
		csv << headers
		for r in records
			csv << r.values
		end
	end
end

# Display the usage
def usage
	puts" MDNSRecon Script by Carlos Perez (carlos_perez[at]darkoperator.com)
Version 0.1
Usage: mdnsrecon.rb [OPTION]
	--help, -h:
		show help
	--csv <file>, -c <file>:
		CSV File to save records found.
	--grep, -g:
		Output grepable Output with a delimiter of \\
		<service>\\domain\\host\\IP\\port\\txt
If no option is given it will print records found to standard output.
"
	exit
end
######################## Main ########################
opts = GetoptLong.new(
	[ '--help', '-h', GetoptLong::NO_ARGUMENT ],
	[ '--csv', '-c', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--grep', "-g" , GetoptLong::NO_ARGUMENT ]
)
grep = false
csvfile = nil
# Parse Options
begin
	opts.each do |opt, arg|
		case opt
		when "--help"
			usage
		when "--csv"
			FileUtils.touch arg
			csvfile = arg
		when "--grep"
			grep = true
		end
	end
rescue
	usage
end

check_avahi
records = get_records
if records.length > 0
	if grep
		print_grep(records)
		exit
	end
	if csvfile
		print_status("Saving found records to #{csvfile}")
		gen_csv(csvfile, records)
		print_good("Records saved")
		exit
	end
	print_records(records)
else
	print_status("No MDNS Records where found in the local subnet")
end