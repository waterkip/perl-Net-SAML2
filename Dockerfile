ARG PERL_VERSION=5.36
FROM perl:$PERL_VERSION

ENV DEBIAN_FRONTEND=noninteractive \
    NO_NETWORK_TESTING=1

WORKDIR /tmp/build


COPY cpanfile .
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends libxml2-dev make gcc \
    && cpanm App::cpm \
    && mkdir -p $HOME/.cpm-perl \
    && wget -q https://src.fedoraproject.org/repo/pkgs/perl-Math-Pari/pari-2.3.4.tar.gz/35c896266e4257793387ba22d5d76078/pari-2.3.4.tar.gz \
        -O pari-2.3.4.tar.gz \
    && echo '35c896266e4257793387ba22d5d76078  pari-2.3.4.tar.gz' | md5sum -c - \
    && tar zxf pari-2.3.4.tar.gz \
    && cd - \
    # cpanminus had a lot of issues with the following packages so we
    # installed them first to trigger failure as soon as possible. Let's see
    # how cpm deals with it
    #&& cpm install -g --test --show-build-log-on-failure Math::Pari \
    #&& cpm install -g --test --show-build-log-on-failure Sub::Name \
    #&& cpm install -g --test --show-build-log-on-failure Package::DeprecationManager \
    #&& cpm install -g --test --show-build-log-on-failure Moose \
    && cpm install -g --test --show-build-log-on-failure --cpanfile cpanfile \
    && rm -rf $HOME/.cpanm $HOME/.cpm-perl
