#!/usr/bin/python

import logging
from glob import glob
from json import loads as load_json
from hashlib import md5
from urllib2 import urlopen, URLError
from urlparse import urljoin
from argparse import ArgumentParser
from pkg_resources import find_distributions


def md5check(path):
    logger = logging.getLogger(__name__)
    with open(path) as fh:
        md5_hash = md5()
        while True:
            chunk = fh.read(128)
            if chunk == '':
                break
            md5_hash.update(chunk)
    file_hash = md5_hash.hexdigest()
    logger.debug('file md5: {0}'.format(file_hash))
    return file_hash


def get_pypi_hash(baseurl):
    logger = logging.getLogger(__name__)
    dist = find_distributions('.').next()
    logger.debug('dist found: {0}'.format(dist))
    targer_url = urljoin(baseurl, 'pypi/{0}/json'.format(dist.project_name))
    logger.debug('opening url: {0}'.format(targer_url))
    response = urlopen(targer_url)
    pypi_json = load_json(response.read())
    md5_digest = pypi_json['releases'][dist.version][0]['md5_digest']
    logger.debug('pypi md5: {0}'.format(md5_digest))
    return md5_digest


def main():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    logger.addHandler(ch)

    parser = ArgumentParser()
    parser.add_argument('-f', '--file',
                        nargs=1,
                        default=glob('dist/*.tar.gz'))
    parser.add_argument('-u', '--url',
                        nargs=1,
                        default=['https://testpypi.python.org/'])
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    ch.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    try:
        file_hash = md5check(args.file[0])
        pypi_hash = get_pypi_hash(args.url[0])
    except (IndexError, IOError):
        logger.error('File not found')
        exit(1)
    except StopIteration:
        logger.error('Distribution not found')
        exit(1)
    except URLError:
        logger.error('Unable to open url')
        exit(1)

    if file_hash == pypi_hash:
        logger.info('Package succesfully uploaded to pypi')
        exit(0)
    else:
        logger.info('Error, package upload failed')
        exit(1)


if __name__ == '__main__':
    main()
