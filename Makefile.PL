use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Test::Taint',
    VERSION_FROM        => 'Taint.pm',
    ABSTRACT            => "Checks for taintedness of variables",
    PREREQ_PM => {
        'Test::More'            => 0,
        'Test::Builder::Tester' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Test-Taint-*' },
);
