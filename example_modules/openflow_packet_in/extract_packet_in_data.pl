#!/usr/bin/env perl

#
# Process the output log for oflops when the openflow_packet_in
# module is used. The script will provide the per packet delay
# for each packet.
#

if(@ARGV < 1) {
    print "Please provide as a param the file to be processed\n";
    exit 1;
}

my $file = $ARGV[0];

if(! -e $file){
    print "Input file not found\n";
    exit 1;
}

open(FILE, "grep OFPT_PACKET_IN_MSG $file | ");

while(!eof(FILE)) {
    $_ = readline(FILE);
    chomp();
    my @data = split(/:/);
    print "$data[4] ".int(($data[3]-$data[2])*(10**6)) ."\n"
};

close(FILE);
