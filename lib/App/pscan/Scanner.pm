package App::pscan::Scanner;
use warnings;
use strict;
use Net::IP;
use App::pscan::Utils;

sub run {
    my $self = shift;
    $self->_gen_range(shift);
    $self->scan();

}

sub _gen_range() {
    my $self = shift;
    my $cmd  = shift;
    my ( $Ip, $Port )
        = ( defined($cmd) and $cmd =~ /:/ )
        ? split( /:/, $cmd )
        : ( $cmd, undef );

    if ( my $IP = new Net::IP($Ip) ) {
        $Ip = $IP;
    }
    elsif ( defined($Ip) ) {
        info "<? Resolving ?> $Ip";
        $Ip = resolve($Ip);
        $Ip = new Net::IP($Ip);
    }

    die( error "-## No ip/hostname to scan ##-" ) if ( !defined($Ip) );
    $self->{'IP'} = $Ip;
    info '-> starting scan <-';
    if ($Port) {
        my ( $f, $l ) = generate_ports($Port);
        $self->{'first'} = $f;
        $self->{'last'}  = $l;
        info 'Scanning for ' . ( ( $l + 1 ) - $f ) . ' port(s)';
    }
}

1;
