#!/usr/bin/perl

package Net::Pcap::Easy::Stats;

use strict;
use warnings;

use DBI;
use Data::Dumper;

sub new {
	my $class = shift;
	my $self = {@_};
	if ( $self->{db} ) {
		$self->{__DBH} = DBI->connect("dbi:SQLite:dbname=$self->{db}", undef, undef, {AutoCommit=>0}) or die $DBI::errstr;
		$self->{__DBH}->do(qq/$_/) foreach ('PRAGMA synchronous = OFF', 'PRAGMA journal_mode = OFF', 'PRAGMA temp_store = MEMORY', 'PRAGMA auto_vacuum = NONE', 'PRAGMA cache_size = 4000000');
		delete $self->{db};
	} else {
		return undef;
	}
	if ( $self->{clear} ) {
		$self->{__DBH}->do(qq/DROP TABLE IF EXISTS streams/);
		$self->{__DBH}->do(qq/DROP TABLE IF EXISTS up_streams/);
		$self->{__DBH}->do(qq/DROP TABLE IF EXISTS down_streams/);
		$self->{__DBH}->do(qq/DROP TABLE IF EXISTS up_frames/);
		$self->{__DBH}->do(qq/DROP TABLE IF EXISTS down_frames/);
		$self->{__DBH}->do(qq/DROP TABLE IF EXISTS requests/);
		$self->{__DBH}->do(qq/DROP TABLE IF EXISTS responses/);
		$self->{__DBH}->do(qq/CREATE TABLE streams (stream_id integer primary key, name text, network text, client text, start real, end real, frames integer, len integer);/);
		$self->{__DBH}->do(qq/  CREATE INDEX idx_streams_len on streams (len);/);
		$self->{__DBH}->do(qq/CREATE TABLE up_streams (up_stream_id integer primary key, stream_id integer, start real, end real, frames integer, len integer);/);
		$self->{__DBH}->do(qq/CREATE TABLE down_streams (down_stream_id integer primary key, stream_id integer, start real, end real, frames integer, len integer);/);
		$self->{__DBH}->do(qq/  CREATE INDEX idx_up_streams_len on up_streams (len);/);
		$self->{__DBH}->do(qq/  CREATE INDEX idx_down_streams_len on down_streams (len);/);
		$self->{__DBH}->do(qq/CREATE TABLE up_frames (up_frame_id integer primary key, up_stream_id integer, time real, len integer);/);
		$self->{__DBH}->do(qq/CREATE TABLE down_frames (down_frame_id integer primary key, down_stream_id integer, time real, len integer);/);
		$self->{__DBH}->do(qq/  CREATE INDEX idx_up_frames_len on up_frames (len);/);
		$self->{__DBH}->do(qq/  CREATE INDEX idx_down_frames_len on down_frames (len);/);
		$self->{__DBH}->do(qq/CREATE TABLE requests (request_id integer primary key, stream_id integer, request_method text, host text, request_uri text, user_agent text);/);
		$self->{__DBH}->do(qq/CREATE TABLE responses (response_id integer primary key, stream_id integer, content_length integer, content_type text);/);
		$self->{__DBH}->do(qq/  CREATE INDEX idx_responses_cl on responses (content_length)/);
		$self->{__DBH}->commit;
		delete $self->{clear};
	}
	$self->{__STRIP_QUERY} = $self->{query} ? 0 : 1 and delete $self->{query};
	$self->{__INTERFACES} = new Net::Pcap::Easy::Interfaces;
	return bless $self, $class;
	#$dbh->do("INSERT INTO test VALUES(null, ?)", undef, int(rand(100)));
}

sub strip_query { shift->{__STRIP_QUERY} }
sub dbh { shift->{__DBH} }
sub interfaces { shift->{__INTERFACES} }
sub stream {
	my $self = shift;
	my $name = shift or return undef;
	$self->{$name} ||= new Net::Pcap::Easy::Stats::Stream;
}
sub frames {
	my $self = shift;
	if ( $_[0] ) {
		$self->{frames} += $_[0];
	}
	return $self->{frames};
}

sub process_pkt {
	my $self = shift;
	my ($npe, $ether, $ip, $tcp, $header) = @_;

	#print Dumper($ether), "\n";
	#print Dumper($ip), "\n";
	#print Dumper($tcp), "\n" x 10;

	my $name = join ' ', sort "$ip->{src_ip}:$tcp->{src_port}", "$ip->{dest_ip}:$tcp->{dest_port}";
	my ($local_ip) = grep { $self->interfaces->is_rfc1918->(map{s/\b0+//g;$_}$_) } $ip->{src_ip}, $ip->{dest_ip};
	my ($interface) = grep { $self->interfaces->list($_)->($local_ip)?$_:'' } $self->interfaces->list;
	$self->frames(1);

	my $stream = $self->stream($name);
	$stream->frames(1);
	$stream->direction($ip->{src_ip} eq $local_ip ? 'U' : 'D');
	$stream->len($header->{len}-$ip->{hlen}-$tcp->{hlen});
	$stream->timestamp($header->{tv_sec}, $header->{tv_usec});

	my $stream_id = $self->add_stream($npe, $ether, $ip, $tcp, $header, $interface, $local_ip, $name) or return;
	$stream->id($stream_id);
	$self->process_payload($tcp => $stream_id);
}

sub process_payload {
	my $self = shift;
	my $packet = shift;
	my $stream_id = shift;
	if ( ref $packet eq 'NetPacket::TCP' ) {
		my $data = $packet->{data};
		my $req = $data if $data =~ /^(GET|POST|DELETE|PUSH)/;
		my $res = $1 if $data =~ /^(HTTP\/\d\.\d \d+ \w+\r\n.*?\r\n\r\n)/s;
		if ( $req ) {
			my ($method, $uri, $host, $agent);
			if ( $data =~ /^(GET|POST|DELETE|HEAD|PUSH) (\/.*?)[\r\n]/ ) {
				$method = $1;
				$uri = $2;
				$uri =~ s/\?.*// if $self->strip_query;
			}
			if ( $data =~ /Host: (.*?)[\r\n]/i ) {
				$host = $1;
			}
			if ( $data =~ /User-Agent: (.*?)[\r\n]/i ) {
				$agent = $1;
			}
			$self->add_request($stream_id, $method, $uri, $host, $agent);
		}
		if ( $res ) {
			my ($cl, $type);
			if ( $data =~ /Content-Length: (.*?)[\r\n]/i ) {
				$cl = $1;
			}
			if ( $data =~ /Content-Type: (.*?)[\r\n]/i ) {
				$type = $1;
			}
			$self->add_response($stream_id, $cl, $type);
		}
	}
}

sub add_stream {
	my $self = shift;
	my ($npe, $ether, $ip, $tcp, $header, $interface, $local_ip, $name) = @_;

	my $stream = $self->stream($name);
	my $stream_id = $self->dbh->selectrow_array(qq/SELECT stream_id FROM streams WHERE name=? LIMIT 1/, undef, $name);
	if ( $stream_id ) {
		$self->dbh->do(qq/UPDATE streams SET len=? WHERE stream_id=?/, undef, $stream->len, $stream->id);
		$self->dbh->commit if $npe->stats->{recv}%100==0;
#		if ( $stream->len > 1_000 ) {
			printf "%s TCP(%s): %s %s (%s %s) -> (%s-%s) -> %s (%s)\n", $stream->timestampf, $self->frames, $interface||'', $local_ip||'', $stream->direction, $name, $stream_id, $stream->frames, $stream->size, $stream->rate('b') if $stream->growth;
#		} else {
#			printf "%s TCP(%s): %s %s (%s %s) -> (%s-%s)\n", $stream->timestampf, $self->frames, $interface||'', $local_ip||'', $stream->direction, $name, $stream_id, $stream->frames if $stream->growth;
#		}
	} else {
		$self->dbh->do(qq/INSERT INTO streams VALUES (null, ?, ?, ?, ?, ?)/, undef, $name, $stream->timestampf, $interface||'', $local_ip||'', $stream->len);
		$stream_id = $self->{__DBH}->func('last_insert_rowid');
		$self->dbh->commit;
#		if ( $stream->len > 1_000 ) {
			printf "%s TCP(%s): %s %s (%s %s) -> (%s-%s) -> %s\n", $stream->timestampf, $self->frames, $interface||'', $local_ip||'', $stream->direction, $name, $stream_id, $stream->frames, $stream->size;
#		} else {
#			printf "%s TCP(%s): %s %s (%s %s) -> (%s-%s)\n", $stream->timestampf, $self->frames, $interface||'', $local_ip||'', $stream->direction, $name, $stream_id, $stream->frames;
#		}
	}
	return $stream_id;
}

sub add_request {
	my $self = shift;
	my ($stream_id, $request_method, $request_uri, $host, $user_agent) = @_;
	$self->dbh->do(qq/INSERT INTO requests VALUES (null, ?, ?, ?, ?, ?)/, undef, $stream_id, $request_method, $request_uri, $host, $user_agent);
	$self->dbh->commit;
	$request_method ||= 'METH';
	$request_uri ||= '?';
	$host ||= '';
	$user_agent ||= '';
	print "$stream_id -> $request_method $host$request_uri\n";
}

sub add_response {
	my $self = shift;
	my ($stream_id, $content_length, $content_type) = @_;
	$self->dbh->do(qq/INSERT INTO responses VALUES (null, ?, ?, ?)/, undef, $stream_id, $content_length, $content_type);
	$self->dbh->commit;
	$content_type ||= 'content/unknown';
	$content_length ||= '___';
	print "$stream_id -> $content_type ($content_length)\n";
}

package Net::Pcap::Easy::Stats::Stream;

use strict;
use warnings;

use Time::HiRes qw/tv_interval/;
use Switch;
use Number::Bytes::Human qw/format_bytes/;
use Time::Stamp -stamps => { dt_sep => ' ', date_sep => '-', us => 1 };

sub new {
	my $class = shift;
	my $self = {
		name => shift,
	};
	return bless $self, $class;
}

sub name { shift->{name} };
sub timestampf { localstamp(shift->timestamp) }
sub elapsed {
	my $self = shift;
	tv_interval(map { $self->$_ } qw/start end/)
}
sub len {
	my $self = shift;
	if ( $_[0] ) {
		$self->{len} += $_[0];
	}
	return $self->{len};
}
sub id {
	my $self = shift;
	if ( $_[0] ) {
		$self->{id} = $_[0];
	}
	return $self->{id};
}
sub frames {
	my $self = shift;
	if ( $_[0] ) {
		$self->{frames} += $_[0];
	}
	return $self->{frames};
}
sub direction {
	my $self = shift;
	if ( $_[0] ) {
		$self->{direction} = $_[0];
	}
	return $self->{direction};
}
sub timestamp {
	my $self = shift;
	if ( $_[0] ) {
		$self->start([@_]);
		$self->end([@_]);
		$self->{timestamp} = join '.', @_;
	}
	return $self->{timestamp};
}
sub start {
	my $self = shift;
	if ( $_[0] ) {
		$self->{start} ||= $_[0];
	}
	return $self->{start};
}
sub end {
	my $self = shift;
	if ( $_[0] ) {
		$self->{end} = $_[0];
	}
	return $self->{end};
}
sub rate {
	my $self = shift;
	#warn $self->len, " / ", $self->elapsed, "\n";
	switch ( $_[0] ) {
		case 'B' { return format_bytes($self->elapsed ? $self->len / $self->elapsed : 0).'Bps' }
		case 'b' { return format_bytes($self->elapsed ? $self->len * 8 / $self->elapsed : 0).'bps' }
		else { return '' }
	}
}
sub size {
	my $self = shift;
	return format_bytes($self->len, @_);
}
sub growth {
	my $self = shift;
	
	my $size = $self->size;
	$size =~ s/\.\d+//;
	$self->{lastsize} ||= '';
	my $growth = $self->{lastsize} eq $size ? 0 : 1;
	#warn $self->{lastsize}, " <=> ", $size, " --> $growth\n";
	$self->{lastsize} = $size;
	#return 1;
	return $growth;
}

package Net::Pcap::Easy::Flow::Interfaces;

use strict;
use warnings;

use NetAddr::IP;
#use Net::Interface 'inet_ntoa';
#use IO::Interface::Simple;
use Net::Subnet;
use Net::Route::Table;

sub new {
	my $class = shift;
	my $self = {};
	$self->{__IS_RFC1918} = subnet_matcher qw(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16);
	my $table_ref = Net::Route::Table->from_system();
	foreach ( @{$table_ref->all_routes} ) {
		$self->{__INTERFACES}->{$_->destination} = subnet_matcher $_->destination;
		print "Identified network: ", $_->destination, "\n";
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

# tcpflow -i any '(src net (10 or 172.16/12 or 192.168/16) or dst net (10 or 172.16/12 or 192.168/16)) and (port 80 or port 443) and not host 172.016.254.248'

use strict;
use warnings;

use Getopt::Long;
use Net::Pcap::Easy;

my $DB = '';
my $CLEAR = 0;
my $QUERY = 0;
GetOptions(
	'db|d=s' => \$DB,
	'clear|c' => \$CLEAR,
	'query|q' => \$QUERY,
);
die "Usage: $0 db\n" unless $DB;

my $flow = new Net::Pcap::Easy::Stats(db=>$DB,clear=>$CLEAR,query=>$QUERY);

my $npe = Net::Pcap::Easy->new(
	dev              => "any",
	#filter           => "host 127.0.0.1 and (tcp or icmp)",
	filter           => "(src net (10 or 172.16/12 or 192.168/16) or dst net (10 or 172.16/12 or 192.168/16)) and (port 80 or port 443) and not net 172.16.254.0/24",
	packets_per_loop => 10,
	bytes_to_capture => 1024,
	timeout_in_ms    => 0, # 0ms means forever
	promiscuous      => 1, # true or false
	tcp_callback     => sub { $flow->process_pkt(@_) },
);

1 while $npe->loop;

__END__

CREATE TABLE streams (stream_id integer primary key, name text, start real, interface text, client text, len integer);
CREATE INDEX idx_len on streams (len);
CREATE TABLE requests (request_id integer primary key, stream_id integer, request_method text, request_uri text, host text, user_agent text);
CREATE TABLE responses (response_id integer primary key, stream_id integer, content_length integer, content_type text);
CREATE INDEX idx_cl on responses (content_length);

sqlite3 libnetaddr-ip-perl libwww-perl libnumber-bytes-human-perl libdbi-perl libdbd-sqlite3-perl libnetpacket-perl libnet-pcap-perl libnet-netmask-perl
cpan Net::Subnet Net::Interface Time::Stamp Net::Pcap::Easy File::Slurp IO::Interface


#select * from (select streams.timestamp,interface,client,host||request_uri,user_agent from streams join requests using (stream_id) where streams.stream_id=175) a, (select streams.timestamp,interface,client,sum(size),sum(content_length) from streams join responses using (stream_id) where streams.stream_id=175) b;
select streams.timestamp,interface,client,host||request_uri,user_agent from streams join requests using (stream_id) where streams.stream like "%58111%";

select streams.timestamp,interface,client,size,host||request_uri,user_agent from streams join requests using (stream_id) order by size;
select streams.timestamp,interface,client,size,content_length,content_type from streams join responses using (stream_id) order by size;


GET /ubuntu-releases//precise/ubuntu-12.04.1-server-amd64.iso HTTP/1.0
User-Agent: Wget/1.12 (linux-gnu)
Accept: */*
Host: mirror.bytemark.co.uk
Connection: Keep-Alive

HTTP/1.1 200 OK
Date: Sat, 22 Sep 2012 15:39:20 GMT
Server: Apache/2.2.16 (Debian)
Last-Modified: Fri, 17 Aug 2012 22:15:49 GMT
ETag: "1dfce0aac-2914b000-4c77d80960f40"
Accept-Ranges: bytes
Content-Length: 689221632
Keep-Alive: timeout=15, max=100
Connection: Keep-Alive
Content-Type: application/x-iso9660-image
