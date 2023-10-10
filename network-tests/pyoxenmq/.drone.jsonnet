local default_deps_base = [
  'python3-dev',
  'python3-setuptools',
  'pybind11-dev',
  'python3-pybind11',
  'liboxenmq-dev',
  'python3-pytest',
  'python3-pip',
];
local default_deps = ['g++'] + default_deps_base;
local docker_base = 'registry.oxen.rocks/lokinet-ci-';

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

// Regular build on a debian-like system:
local debian_pipeline(name,
                      image,
                      arch='amd64',
                      deps=default_deps,
                      extra_cmds=[],
                      jobs=6,
                      loki_repo=true,
                      allow_fail=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  steps: [
    {
      name: 'build',
      image: image,
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: [
                  'echo "Building on ${DRONE_STAGE_MACHINE}"',
                  'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                  apt_get_quiet + ' update',
                  apt_get_quiet + ' install -y eatmydata',
                ] + (
                  if loki_repo then [
                    'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y lsb-release',
                    'cp contrib/deb.oxen.io.gpg /etc/apt/trusted.gpg.d',
                    'echo deb http://deb.oxen.io $$(lsb_release -sc) main >/etc/apt/sources.list.d/oxen.list',
                    'echo deb http://deb.oxen.io/beta $$(lsb_release -sc) main >>/etc/apt/sources.list.d/oxen.list',
                    'echo deb http://deb.oxen.io/staging $$(lsb_release -sc) main >>/etc/apt/sources.list.d/oxen.list',
                    'eatmydata ' + apt_get_quiet + ' update',
                  ] else []
                ) + [
                  'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                  'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y ' + std.join(' ', deps),
                  'CFLAGS="-Wextra -Werror -fdiagnostics-color" pip3 install . -v',
                  'py.test-3 -v --color=yes',
                ]
                + extra_cmds,
    },
  ],
};

// Macos build
local mac_builder(name,
                  extra_cmds=[],
                  jobs=6,
                  allow_fail=false) = {
  kind: 'pipeline',
  type: 'exec',
  name: name,
  platform: { os: 'darwin', arch: 'amd64' },
  steps: [
    {
      name: 'build',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        'mkdir prefix',
        'git clone https://github.com/oxen-io/oxen-mq.git',
        'cd oxen-mq',
        'git submodule update --init --recursive --depth=1',
        'mkdir build && cd build',
        'cmake .. -DOXENMQ_BUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX=../../prefix -G Ninja',
        'ninja install -j' + jobs,
        'cd ../..',
        'LDFLAGS="-L$$PWD/prefix/lib -L/opt/local/lib" ' +
        'CFLAGS="-Wextra -Werror -fcolor-diagnostics -I$$PWD/prefix/include -I/opt/local/include" ' +
        'python3 -mpip install . -v --prefix=./prefix',
        'DYLD_LIBRARY_PATH=$$PWD/prefix/lib PYTHONPATH=$$(ls -1d $$PWD/prefix/lib/python3*/site-packages) python3 -mpytest -v --color=yes',
      ] + extra_cmds,
    },
  ],
};


[
  // Various debian builds
  debian_pipeline('Debian sid (amd64)', docker_base + 'debian-sid'),
  debian_pipeline('Debian stable (i386)', docker_base + 'debian-stable/i386'),
  debian_pipeline('Debian buster (amd64)', docker_base + 'debian-buster'),
  debian_pipeline('Ubuntu latest (amd64)', docker_base + 'ubuntu-rolling'),
  debian_pipeline('Ubuntu LTS (amd64)', docker_base + 'ubuntu-lts'),

  // ARM builds (ARM64 and armhf)
  debian_pipeline('Debian sid (ARM64)', docker_base + 'debian-sid', arch='arm64', jobs=4),
  debian_pipeline('Debian stable (armhf)', docker_base + 'debian-stable/arm32v7', arch='arm64', jobs=4),

  // Macos builds:
  mac_builder('macOS'),
]
