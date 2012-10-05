#!/usr/bin/perl

package Net::Pcap::Easy::DPI;

use strict;
use warnings;

use DBI;
use Net::Pcap::Easy;
use Data::Dumper;

sub new {
	my $class = shift;
	my $db = shift;
	my $self = {@_};
	if ( $db ) {
		$self->clear(1) unless -e $db;
		$self->{__DBH} = DBI->connect("dbi:SQLite:dbname=$db", undef, undef, {AutoCommit=>0}) or die $DBI::errstr;
		$self->dbi->do(qq/$_/) foreach ('PRAGMA synchronous = OFF', 'PRAGMA journal_mode = OFF', 'PRAGMA temp_store = MEMORY', 'PRAGMA auto_vacuum = NONE', 'PRAGMA cache_size = 4000000');
	} else {
		return undef;
	}
	$self->{__INTERFACES} = new Net::Pcap::Easy::DPI::Interfaces;
	return bless $self, $class;
}
sub dbh { shift->{__DBH} }
sub interfaces { shift->{__INTERFACES} }
sub clear {
	my $self = shift;
	if ( $_[0] ) {
		warn "Setting up $db\n";
		$self->dbh->do(qq/DROP TABLE IF EXISTS streams/);
		$self->dbh->do(qq/DROP TABLE IF EXISTS up_streams/);
		$self->dbh->do(qq/DROP TABLE IF EXISTS down_streams/);
		$self->dbh->do(qq/DROP TABLE IF EXISTS up_frames/);
		$self->dbh->do(qq/DROP TABLE IF EXISTS down_frames/);
		$self->dbh->do(qq/DROP TABLE IF EXISTS requests/);
		$self->dbh->do(qq/DROP TABLE IF EXISTS responses/);
		$self->dbh->do(qq/CREATE TABLE streams (stream_id integer primary key, name text, network text, client text, start real, end real, frames integer, len integer);/);
		$self->dbh->do(qq/  CREATE INDEX idx_streams_len on streams (len);/);
		$self->dbh->do(qq/CREATE TABLE up_streams (up_stream_id integer primary key, stream_id integer, start real, end real, frames integer, len integer);/);
		$self->dbh->do(qq/CREATE TABLE down_streams (down_stream_id integer primary key, stream_id integer, start real, end real, frames integer, len integer);/);
		$self->dbh->do(qq/  CREATE INDEX idx_up_streams_len on up_streams (len);/);
		$self->dbh->do(qq/  CREATE INDEX idx_down_streams_len on down_streams (len);/);
		$self->dbh->do(qq/CREATE TABLE up_frames (up_frame_id integer primary key, up_stream_id integer, time real, len integer);/);
		$self->dbh->do(qq/CREATE TABLE down_frames (down_frame_id integer primary key, down_stream_id integer, time real, len integer);/);
		$self->dbh->do(qq/  CREATE INDEX idx_up_frames_len on up_frames (len);/);
		$self->dbh->do(qq/  CREATE INDEX idx_down_frames_len on down_frames (len);/);
		$self->dbh->do(qq/CREATE TABLE requests (request_id integer primary key, stream_id integer, request_method text, host text, request_uri text, user_agent text);/);
		$self->dbh->do(qq/  CREATE INDEX idx_requests_stream_id on requests (stream_id)/);
		$self->dbh->do(qq/  CREATE INDEX idx_requests_request on requests (request_method, host, request_uri)/);
		$self->dbh->do(qq/  CREATE INDEX idx_requests_user_agent on requests (user_agent)/);
		$self->dbh->do(qq/CREATE TABLE responses (response_id integer primary key, stream_id integer, content_length integer, content_type text);/);
		$self->dbh->do(qq/  CREATE INDEX idx_responses_stream_id on responses (stream_id)/);
		$self->dbh->do(qq/  CREATE INDEX idx_responses_cl on responses (content_length)/);
		$self->dbh->commit;
		$self->{__CLEAR} = 1;
	}
	return $self->{__CLEAR};
}
sub strip_query {
	my $self = shift;
	$self->{__STRIP_QUERY} = 1 if $_[0];
	return $self->{__STRIP_QUERY};
}

package Net::Pcap::Easy::DPI::HTTP;

use strict;
use warnings;

use base 'Net::Pcap::Easy::DPI';

sub npe {
	my $self = shift;
	my $http_dpi = new Net::Pcap::Easy::DPI::HTTP;
	return Net::Pcap::Easy->new(
		dev => "any",
		filter => "(src net (10 or 172.16/12 or 192.168/16) or dst net (10 or 172.16/12 or 192.168/16)) and (port 80 or port 443) and not net 172.16.254.0/24",
		packets_per_loop => 10,
		bytes_to_capture => 1024,
		timeout_in_ms => 0, # 0ms means forever
		promiscuous => 1, # true or false
		tcp_callback => sub { $http_dpi->process_pkt(@_) },
	);
}

sub process_pkt {
	my $self = shift;
	my ($npe, $ether, $ip, $tcp, $header) = @_;
	warn Dumper($header);
}

package Net::Pcap::Easy::DPI::Interfaces;

use strict;
use warnings;

use Net::Subnet;
use Net::Route::Table;
use NetAddr::IP;

sub new {
	my $class = shift;
	my $self = {};
	$self->{__IS_RFC1918} = subnet_matcher qw(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16);
	my $table_ref = Net::Route::Table->from_system();
	foreach ( grep { !m!^0\.0\.0\.0/0! } @{$table_ref->all_routes} ) {
		$self->{__INTERFACES}->{$_->destination} = subnet_matcher $_->destination;
		print "Identified network for deep-packet inspection: ", $_->destination, "\n";
	}
	return bless $self, $class;
}

sub list {
	my $self = shift;
	return $self->{__INTERFACES}->{$_[0]} if $_[0];
	return keys %{$self->{__INTERFACES}};
}
sub is_rfc1918 { shift->{__IS_RFC1918} }

package main;

use strict;
use warnings;

use Getopt::Long;

my $clear = 0;
my $strip_query = 0;
GetOptions(
	'clear|c' => \$clear,
	'strip-query|q' => \$strip_query,
);
my $db = shift @ARGV;
die "Usage: $0 [-cq] db\n" unless $db;

my $http_dpi = new Net::Pcap::Easy::DPI::HTTP($db);
$http_dpi->clear($clear);
$http_dpi->strip_query($strip_query);
1 while $http_dpi->npe->loop;
