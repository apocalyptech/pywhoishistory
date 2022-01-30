#!/usr/bin/env python3
# vim: set expandtab tabstop=4 shiftwidth=4:

# Copyright 2022 Christopher J. Kucera
# <cj@apocalyptech.com>
# <http://apocalyptech.com/contact.php>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the development team nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL CJ KUCERA BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import re
import sys
import enum
import time
import whois
import appdirs
import MySQLdb
import argparse
import datetime
import configparser
import dns.resolver

__version__ = '1.0.1'

class DNSBehavior(enum.Enum):
    DOMAIN_DEFAULT = enum.auto()
    FORCE_YES = enum.auto()
    FORCE_NO = enum.auto()

class App:
    """
    The application itself.  Handles, y'know, all the things.

    The majority of the data we're storing/comparing is just from whois, but we're
    also doing a couple of basic DNS lookups (A/AAAA/MX) on the domain record
    itself.

    Some notes on the schema:

        param - App parameters; a string-based key/value store.  At the moment
            this is only used to store a `db_ver` key, which will let us know
            if the database ever needs updating in the future.

        state - A point-in-time state of a domain's whois/dns lookups.  Includes
            both the raw text of the whois lookup, plus all the python-whois-parsed
            information in separate fields.  Consecutive `state` entries for a
            single domain should contain at least one difference between them.

        domain - A "master" list of domains that we're checking.  Links to the
            most recent `state` where any changes were detected (or the original
            `state`, if there have been no changes since the original).  It also
            contains a raw text of the most *recent* whois lookup, which could
            potentially differ from the most recent `state`, if the whois servers
            start formatting text differently.  (Obviously if they start formatting
            *too* differently, it may throw off python-whois's parsing anyway, and
            generate a new `state`.)

        changed - This is a pretty stupid table, really, which just provides some
            to/from info, related to a specific `state`, along with an English
            label to go along with each row.  Obviously this could be done by an
            app just looking through the `state` table (so long as the app supplies
            its own English labels, anyway), but I liked the idea of being able
            to trivially dump a table with that info, rather than having to do
            those comparisons at display-time, too.  c'est la vie.

    """

    # Datapoints we'll compare on, and their English labels for the `changed` table.
    datapoints = {
            'registrar': 'Registrar',
            'whois_server': 'WHOIS Server',
            'referral_url': 'Referral URL',
            'updated_date': 'Updated Date',
            'creation_date': 'Creation Date',
            'expiration_date': 'Expiration Date',
            'name_servers': 'Nameservers',
            'status': 'Status',
            'emails': 'Emails',
            'dnssec': 'DNSSEC',
            'name': 'Registrant Name',
            'org': 'Registrant Organization',
            'address': 'Registrant Address',
            'city': 'Registrant City',
            'state': 'Registrant State',
            'zipcode': 'Registrant Zipcode',
            'ip': 'IP Address',
            'mx': 'MX Addresses',
            }

    # Regex for processing some alternate date formats we might see, which
    # python-whois itself doesn't auto-detect.
    date_t_re = re.compile('^(?P<year>\d+)-(?P<month>\d+)-(?P<day>\d+)T(?P<hour>\d+):(?P<min>\d+):(?P<sec>\d+)$')

    # Regex to remove URLs from statuses
    status_url_re = re.compile('^(?P<status>.*?)( \(?(?P<url>http\S+?)\)?)?$')

    def __init__(self, dns_behavior, delay_between_domains, max_retries, verbose=False):
        self.dns_behavior = dns_behavior
        self.delay_between_domains = delay_between_domains
        self.max_retries = max_retries
        self.verbose = verbose
        self._read_config()
        self._connect_db()
        self._init_db()

    def exit(self, retval):
        """
        Exit the app, returning the specified `retval`.  Closes all DB handles first.
        Basically just doing this 'cause using __enter__ and __exit__ seemed like
        overkill.
        """
        self.close()
        sys.exit(retval)

    def _read_config(self):
        """
        Read our config file from the filesystem, or create a template config file
        if it's not present.  Will print a message to the user and exit the app if
        a file needed to be created.

        At the moment, the only configuration found in here is the DB connection info.
        """
        self.config_dir = appdirs.user_config_dir('pywhoishistory', 'apocalyptech')
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir, exist_ok=True)
        self.config_file = os.path.join(self.config_dir, 'app.ini')
        if not os.path.exists(self.config_file):
            config = configparser.ConfigParser()
            config['database'] = {
                    'hostname': 'HOSTNAME',
                    'port': 3306,
                    'dbname': 'DBNAME',
                    'username': 'USERNAME',
                    'password': 'PASSWORD',
                    }
            with open(self.config_file, 'w') as odf:
                config.write(odf)
            print(f'Example config written to {self.config_file}')
            print('Add database parameters there and restart.')
            sys.exit(1)
        self.config = configparser.ConfigParser()
        self.config.read(self.config_file)
        try:
            _ = int(self.config['database']['port'])
        except ValueError:
            print('ERROR: Configured database port is not an integer: {}'.format(
                self.config['database']['port'],
                ))
            print(f'Check the configuration in: {self.config_file}')
            sys.exit(1)

    def _connect_db(self):
        """
        Connect to our database
        """
        try:
            self.db = MySQLdb.connect(
                    host=self.config['database']['hostname'],
                    port=int(self.config['database']['port']),
                    user=self.config['database']['username'],
                    passwd=self.config['database']['password'],
                    db=self.config['database']['dbname'],
                    use_unicode=True,
                    charset='utf8',
                    )
        except MySQLdb._exceptions.OperationalError as e:
            print(f'Error connecting to database: {e.args[1]}')
            print(f'Verify that parameters are correct in {self.config_file}')
            sys.exit(1)
        self.cur = self.db.cursor(MySQLdb.cursors.DictCursor)
        self.cur.execute('SET @@sql_mode:=TRADITIONAL')
        self._refresh_tables()

    def _refresh_tables(self):
        """
        Refresh our list of known tables, used elsewhere in the app to figure out if
        we need to create the schema ourselves.
        """
        self.db_tables = set()
        self.cur.execute('show tables')
        for row in self.cur.fetchall():
            self.db_tables.add(row['Tables_in_{}'.format(self.config['database']['dbname'])])

    def _table_exists(self, tablename):
        """
        Returns `True` if the specified `tablename` exists in the database, or `False`
        otherwise.
        """
        return tablename in self.db_tables

    def _init_db(self):
        """
        Initializes our database.  If our tables are not found, they will be created.
        If the tables *are* found, the internal DB version will be compared and the
        database will be upgraded if need be.

        My intention, for now, is that in the event of the database not being found,
        this function will create a v1 database and then step through each upgrade,
        rather than creating the most recent version "directly."  That way the upgrade
        path is easier to test.  We'll see if I stick with that when/if I ever have
        database updates.

        Database version history:
         - v1: Initial release
        """

        max_db_ver = 1

        # Create our database, if need be
        if not self._table_exists('param'):

            if self.verbose:
                print('NOTE: Creating initial database')

            # If we don't have param but *do* have other tables, who knows
            # what's going on?  Abort.
            for table in [
                    'state',
                    'domain',
                    'change',
                    ]:
                if self._table_exists(table):
                    print(f'WARNING: {table} already exists on a v0/new database.  Aborting!')
                    self.exit(1)

            # Now get to the creatin'.
            self.cur.execute("""
                create table param (
                    param varchar(64) not null,
                    value varchar(64) not null,
                    primary key (param)
                    ) engine=innodb
                """)
            self.cur.execute("""
                create table state (
                    id int not null auto_increment,
                    domain varchar(255),
                    check_time datetime,
                    raw_text text,
                    registrar varchar(255),
                    whois_server varchar(255),
                    referral_url varchar(255),
                    updated_date datetime,
                    creation_date datetime,
                    expiration_date datetime,
                    name_servers varchar(255),
                    status varchar(255),
                    emails varchar(255),
                    dnssec varchar(255),
                    name varchar(255),
                    org varchar(255),
                    address varchar(255),
                    city varchar(255),
                    state varchar(255),
                    zipcode varchar(255),
                    ip varchar(255),
                    mx varchar(255),
                    primary key (id),
                    unique index domtime_idx (domain, check_time)
                    ) engine=innodb
                """)
            self.cur.execute("""
                create table domain (
                    domain varchar(255),
                    last_state int,
                    active_checks boolean default 1,
                    do_dns boolean default 1,
                    last_checked datetime,
                    cur_raw_text text,
                    primary key (domain),
                    foreign key (last_state) references state (id)
                    ) engine=innodb
                """)
            self.cur.execute("""
                create table changed (
                    id int not null auto_increment,
                    state int,
                    info varchar(64),
                    val_from varchar(255),
                    val_to varchar(255),
                    primary key (id),
                    unique index info_idx (state, info),
                    foreign key (state) references state (id)
                    ) engine=innodb
                """)
            self.cur.execute("""
                alter table state
                add constraint fk_domain foreign key (domain) references domain (domain)
                """)
            self.db.commit()
            self._refresh_tables()

            # Set the initial version
            self.set_param('db_ver', max_db_ver)
            db_ver = max_db_ver

        else:

            # Get our database version
            db_ver = self.get_param_int('db_ver')

        # Output a notice about upgrading the DB, if appropriate
        if db_ver < max_db_ver and self.verbose:
            print(f'NOTICE: Upgrading database to version {max_db_ver}')

        # Bring the database up to snuff, if needed
        if db_ver < 2:
            pass

    def wipe_db(self):
        """
        Removes all our tables from the database, allowing the next run to start fresh.
        """
        if self.verbose:
            print('WARNING: Wiping database')
        try:
            self.cur.execute('alter table state drop foreign key fk_domain')
        except MySQLdb._exceptions.OperationalError:
            # This can happen if the fk doesn't exist
            pass
        except MySQLdb._exceptions.ProgrammingError:
            # This can happen if the `state` table itself doesn't exist
            pass
        self.cur.execute('drop table if exists changed')
        self.cur.execute('drop table if exists domain')
        self.cur.execute('drop table if exists state')
        self.cur.execute('drop table if exists param')
        self.db.commit()
        self._refresh_tables()

    def get_param(self, param):
        """
        Get the specified `param` from our app parameters table.  At the moment the
        only valid key is `db_ver`, which contains the database version.  Will return
        `None` if the key is not found.
        """
        self.cur.execute("""
            select value
            from param
            where param=%s
            """, (param,))
        row = self.cur.fetchone()
        if not row:
            return None
        else:
            return row['value']

    def get_param_int(self, param):
        """
        Gets the specified `param` from our app parameters table as an integer.
        Will default to -1 if the parameter is not found in the table, and exit the
        app if the value in the DB cannot be converted to an integer.
        """
        value = self.get_param(param)
        if value is None:
            return -1
        else:
            try:
                return int(value)
            except ValueError:
                print(f'ERROR: Unknown integer value for {param}: {value}')
                self.exit(1)

    def set_param(self, param, value):
        """
        Sets the specified `param` in our app parameters table, to the value `value`.
        Will create the `param` entry if needed.
        """
        cur_val = self.get_param(param)
        if cur_val is None:
            self.cur.execute("""
                insert into param (param, value)
                values (%s, %s)
                """, (param, value))
        else:
            self.cur.execute("""
                update param
                set value=%s
                where param=%s
                """, (value, param))
        self.db.commit()

    def close(self):
        """
        Close our open cursor and database handle.
        """
        self.cur.close()
        self.cur = None
        self.db.close()
        self.db = None
        self.db_tables = set()

    def check_all_domains(self):
        """
        Loop through all known domains in the database and check the whois/dns
        status of each one, pausing inbetween for the configured number of seconds.

        This function will return `True` if changes were detected on any of the
        domains in the DB, or `False` otherwise.
        """

        # Get a list of all domains
        domains = set()
        self.cur.execute('select domain from domain where active_checks=1')
        for row in self.cur:
            domains.add(row['domain'])

        # Now loop through 'em all
        have_changes = False
        first = True
        for domain in sorted(domains):
            if not first:
                if self.verbose:
                    print(f'Waiting {self.delay_between_domains} seconds...')
                    print('')
                time.sleep(self.delay_between_domains)
            if self.check_domain(domain):
                have_changes = True
            first = False

        # Return
        return have_changes

    def check_domain(self, domain, check_data=None):
        """
        Checks the whois/dns status for the given `domain`.  If `check_data` is not
        `None`, that data will be used instead of making a "live" whois call to the
        internet.  `check_data` is primarily intended to be used to avoid running
        into ratelimiting issues when testing out the application.

        This function will return `True` if any changes were detected since the last
        run, or `False` otherwise.
        """

        # Report, if verbose
        if self.verbose:
            print(f'{domain} - Running checks...')

        # First check to see if the domain's in our DB, and add it if not
        self.cur.execute('select * from domain where domain=%s', (domain,))
        row = self.cur.fetchone()
        if row is None:
            if self.verbose:
                print(f'{domain} - Adding to the database')
            if self.dns_behavior == DNSBehavior.FORCE_NO:
                do_dns_db = 0
                do_dns = False
            else:
                do_dns_db = 1
                do_dns = True
            self.cur.execute("""
                insert into domain (domain, active_checks, do_dns)
                values (%s, 1, %s)
                """, (domain, do_dns_db))
            self.db.commit()
        else:
            if self.dns_behavior == DNSBehavior.FORCE_YES:
                if self.verbose and row['do_dns'] == 0:
                    print(f'{domain} - Enabling DNS lookups')
                do_dns = True
            elif self.dns_behavior == DNSBehavior.FORCE_NO:
                if self.verbose and row['do_dns'] == 1:
                    print(f'{domain} - Disabling DNS lookups')
                do_dns = False
            else:
                do_dns = (row['do_dns'] == 1)

        # Do the whois call, if we weren't passed dummy data, and then parse it.
        # We're interested in getting both the "raw" text info plus python-whois's
        # parsed info, so we're mimicing the behavior of `whois.whois()` here.
        # This may not be 100% future-API-proof, 'cause I'm not sure which of
        # these calls are intended to be stable.
        if check_data is None:
            client = whois.NICClient()
            attempts = 0
            while attempts < self.max_retries:
                attempts += 1
                check_data = client.whois_lookup(None, domain.encode('idna'), 0)
                if attempts < self.max_retries and 'Socket not responding' in check_data:
                    if self.verbose:
                        print(f'{domain} - Communication error, pausing {self.delay_between_domains} seconds to retry...')
                    time.sleep(self.delay_between_domains)
                else:
                    break
        if 'Socket not responding' in check_data:
            print(f'{domain} - Communication error while checking whois.  Not storing results.')
            return True
        parsed_data = whois.WhoisEntry.load(domain, check_data)

        # Massage the parsed data a bit
        self._clean_parsed_data(domain, parsed_data)

        # And inject some DNS lookups as well, if we're supposed to
        if do_dns:
            self._inject_dns_lookups(domain, parsed_data)
        else:
            self._inject_dns_placeholder(parsed_data)

        # Update the database
        return self._store_state(domain, check_data, parsed_data, do_dns)

    def _clean_parsed_data(self, domain, parsed_data):
        """
        The parsed output from python-whois needs a bit of massaging to get it in
        a state that we can just arbitrarily loop through the elements and do
        the same processing on them.  This will make those changes in-place in
        the `parsed_data` dict.
        """

        # First up: date processing.  All three of these dates *might* be
        # lists (but might not), and might be a datetime.datetime object, or
        # might be a string.  They also might contain microseconds, which we
        # don't want because the DB only stores up to seconds (so if we compare
        # directly we'd have perpetual mismatches).  Additionally, in cases
        # where there *are* differences, we're only concerned with the most
        # recent/oldest, depending on what we're looking at.  Also additionally,
        # some results may mix timezone-aware and non-timezone-aware datetime
        # objects.  If we see *any* non-timezone-aware objects, we're going to
        # just force them to UTC.
        for key, func in [
                ('updated_date', max),
                ('creation_date', min),
                ('expiration_date', min),
                ]:
            if type(parsed_data[key]) == list:
                dates = parsed_data[key]
            else:
                dates = [parsed_data[key]]
            new_dates = []
            for date in dates:
                if type(date) == datetime.datetime:
                    # Clear microseconds, and also strip timezone (since the DB doesn't
                    # store that, and otherwise we'd have mismatches)
                    if date.tzinfo is None:
                        new_dates.append(date.replace(microsecond=0))
                    else:
                        new_dates.append(datetime.datetime(
                            date.year,
                            date.month,
                            date.day,
                            date.hour,
                            date.minute,
                            date.second,
                            ))
                else:
                    # Still running Python 3.6 on this server, so no walrus op for me
                    match = self.date_t_re.match(date)
                    if match:
                        new_dates.append(datetime.datetime(
                            int(match.group('year')),
                            int(match.group('month')),
                            int(match.group('day')),
                            int(match.group('hour')),
                            int(match.group('min')),
                            int(match.group('sec')),
                            ))
                    else:
                        print(f'ERROR: Unknown date format in {domain}: {date}')
                        self.exit(1)
            parsed_data[key] = func(new_dates)

        # Now name_servers -- get rid of duplicates
        name_servers = set()
        for ns in parsed_data['name_servers']:
            name_servers.add(ns.lower())
        parsed_data['name_servers'] = ', '.join(sorted(name_servers))

        # Status -- might show up as a list.  Also, strip off the URLs because
        # those don't really add any info that'd be useful to us, and can lead
        # to some real long strings
        if type(parsed_data['status']) == list:
            statuses = parsed_data['status']
        else:
            statuses = [parsed_data['status']]
        new_statuses = set()
        for status in statuses:
            match = self.status_url_re.match(status)
            if match:
                new_statuses.add(match.group('status'))
            else:
                new_statuses.add(status)
        parsed_data['status'] = ', '.join(sorted(new_statuses))

        # Emails -- likely to show up as a list
        if type(parsed_data['emails']) == list:
            parsed_data['emails'] = ', '.join(sorted(parsed_data['emails']))

    def _inject_dns_lookups(self, domain, parsed_data):
        """
        Given the domain `domain`, do DNS lookups for A/AAAA/MX records on the
        top-level domain itself, and inject those values into the `parsed_data`
        dict.
        """

        # Main A/AAAA record(s) of the domain itself
        ips = set()
        try:
            answers = dns.resolver.query(domain, 'A')
            for rdata in answers:
                ips.add(rdata.address)
        except dns.resolver.NoAnswer:
            pass
        try:
            answers = dns.resolver.query(domain, 'AAAA')
            for rdata in answers:
                ips.add(rdata.address)
        except dns.resolver.NoAnswer:
            pass
        parsed_data['ip'] = ', '.join(sorted(ips))

        # Now MXes
        mx = set()
        try:
            answers = dns.resolver.query(domain, 'MX')
            for rdata in answers:
                exch = str(rdata.exchange)
                if exch.endswith('.'):
                    exch = exch[:-1]
                mx.add(f'{rdata.preference}/{exch}')
        except dns.resolver.NoAnswer:
            pass
        parsed_data['mx'] = ', '.join(sorted(mx))

    def _inject_dns_placeholder(self, parsed_data):
        """
        Inserts "placeholder" DNS info into `parsed_data`, for domains which don't
        want to have DNS info stored
        """
        parsed_data['ip'] = '(lookups disabled)'
        parsed_data['mx'] = '(lookups disabled)'

    def _store_state(self, domain, check_data, parsed_data, do_dns):
        """
        Conditionally store the state of a whois/dns lookup in the database.  `domain`
        should be the domain that was queried; `check_data` is the raw whois data,
        and `parsed_data` is a dictionary returned by python-whois.  `do_dns` is a
        boolean describing if we queried DNS to do the lookups -- this is just used
        to update that boolean in the `domain` table on the DB.

        If this is the first time the given `domain` has been seen in the database,
        its initial state will be recorded.  If there's an existing state for `domain`,
        the data will be compared and a new state will only be recorded if any
        mismatches are detected.

        This function will return `True` if changes were detected, or `False` otherwise.

        Note that if any changes are detected, this function will output text to the
        terminal, regardless of our `verbose` setting.
        """

        # Some control vars
        store_state = False
        differences = []

        # First get the most recent state for the domain, for comparison (if it exists)
        self.cur.execute("""
            select last_state from domain
            where domain=%s
            """, (domain,))
        row = self.cur.fetchone()
        if row and row['last_state'] is not None:
            self.cur.execute("""
                select * from state
                where id=%s
                """, (row['last_state'],))
            prev_state = self.cur.fetchone()

            # Find out if there are differences
            for key, eng in self.datapoints.items():
                if prev_state[key] != parsed_data[key]:
                    if not store_state:
                        print(f'{domain} - Changes detected:')
                    print(f' - {eng}: {prev_state[key]} -> {parsed_data[key]}')
                    store_state = True
                    differences.append((eng, prev_state[key], parsed_data[key]))
        else:
            # We have no previous data -- always store our new state
            store_state = True
            print(f'{domain} - Initial state being recorded')

        # No matter what, we update last_checked, do_dns, and cur_raw_text
        self.cur.execute("""
            update domain
            set cur_raw_text=%s, last_checked=now(), do_dns=%s
            where domain=%s
            """, (check_data, do_dns, domain))

        # Now store the new state, if appropriate
        if store_state:
            self.cur.execute("""
                insert into state
                    (domain, check_time, raw_text,
                    registrar, whois_server, referral_url,
                    updated_date, creation_date, expiration_date,
                    name_servers, status, emails, dnssec,
                    name, org,
                    address, city, state, zipcode,
                    ip, mx
                    )
                values
                    (%s, now(), %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s,
                    %s, %s, %s, %s,
                    %s, %s
                    )
                """, (
                    domain,
                    check_data,
                    parsed_data['registrar'],
                    parsed_data['whois_server'],
                    parsed_data['referral_url'],
                    parsed_data['updated_date'],
                    parsed_data['creation_date'],
                    parsed_data['expiration_date'],
                    parsed_data['name_servers'],
                    parsed_data['status'],
                    parsed_data['emails'],
                    parsed_data['dnssec'],
                    parsed_data['name'],
                    parsed_data['org'],
                    parsed_data['address'],
                    parsed_data['city'],
                    parsed_data['state'],
                    parsed_data['zipcode'],
                    parsed_data['ip'],
                    parsed_data['mx'],
                    ))
            new_state_id = self.cur.lastrowid

            # Update the domain itself with the new state
            self.cur.execute("""
                update domain
                set last_state=%s
                where domain=%s
                """, (new_state_id, domain))

            # Store any differences that we found
            for info, val_from, val_to in differences:
                self.cur.execute("""
                    insert into changed (state, info, val_from, val_to)
                    values (%s, %s, %s, %s)
                    """, (new_state_id, info, val_from, val_to))

        # Finally, commit all our changes
        self.db.commit()

        # Newline inbetween domains
        if store_state:
            print('')
        elif self.verbose:
            print(f'{domain} - No changes to report!')
            print('')

        # Return whether or not we had a new state to store
        return store_state

    def _have_domain(self, domain):
        """
        Returns `True` if `domain` is found in the database, or `False` otherwise.
        """
        self.cur.execute('select domain from domain where domain=%s', (domain,))
        row = self.cur.fetchone()
        if row:
            return True
        else:
            return False

    def set_domain_status(self, domain, active_checks=True):
        """
        Sets the specified `domain`'s `active_checks` status to the given value.
        Newly-created domains are already set to have active checks enabled.
        """

        # This isn't really necessary, but we'll check to make sure we know about
        # the domain, first.
        if not self._have_domain(domain):
            print(f'WARNING: domain {domain} not found in database')
            self.exit(1)

        # Now update the flag regardless of its current value (which would just
        # silently do nothing, if the domain wasn't found)
        if active_checks:
            val_to_set=1
            report = 'enabled'
        else:
            val_to_set=0
            report = 'disabled'
        self.cur.execute("""
            update domain
            set active_checks=%s
            where domain=%s
            """, (val_to_set, domain))
        self.db.commit()

        # Report
        if self.verbose:
            print(f'Active checks for {domain} {report}')

    def _get_state_ids(self, domain):
        """
        Given a `domain`, return list of tuples describing the states which exist for
        the domain.  The first element of the tuple is the `state` ID, and the second
        is the timestamp for that state.  The list will be sorted from oldest to
        newest.
        """
        states = []
        self.cur.execute("""
            select id, check_time from state
            where domain=%s
            order by check_time asc
            """, (domain,))
        for row in self.cur:
            states.append((row['id'], row['check_time']))
        return states

    def purge_domain(self, domain):
        """
        Purges the specified domain from the database entirely (removes all
        `changed` records and all `state`s, in addition to the `domain`
        entry itself).
        """

        # This isn't really necessary, but we'll check to make sure we know about
        # the domain, first.
        if not self._have_domain(domain):
            print(f'WARNING: domain {domain} not found in database')
            self.exit(1)
        
        # Get a list of states
        states = self._get_state_ids(domain)
        state_in_param_sql = ','.join(['%s' for s in states])
        state_in_list = [s[0] for s in states]

        # Clear out any `changed` entries which correspond
        if states:
            self.cur.execute("""
                delete from changed
                where state in ({})
                """.format(state_in_param_sql), state_in_list)

        # Disassociate our `domain` record from its `last_state`, so
        # that deleting states doesn't result in foreign key violations
        self.cur.execute("""
            update domain
            set last_state=null
            where domain=%s
            """, (domain,))

        # Delete all states
        if states:
            self.cur.execute("""
                delete from state
                where id in ({})
                """.format(state_in_param_sql), state_in_list)

        # Delete the domain record
        self.cur.execute("""
            delete from domain
            where domain=%s
            """, (domain,))

        # Commit
        self.db.commit()

        # Report
        if self.verbose:
            print(f'{domain} purged from database')

    def get_domains(self):
        """
        Returns a list of tuples, with the following data:
            Index 0: A domain name found in the database
            Index 1: A boolean which is `True` if active checks are enabled
                     for the domain, and `False` otherwise.
            Index 2: A boolean which is `True` if DNS lookups are active
                     for the domain, and `False` otherwise.
        The list will be sorted by the domain name.
        """

        to_ret = []
        self.cur.execute("""
            select domain, active_checks, do_dns from domain
            order by domain
            """)
        for row in self.cur:
            to_ret.append((row['domain'], row['active_checks'] == 1, row['do_dns'] == 1))
        return to_ret

    def show_domains(self):
        """
        Outputs a human-readable list of available domains in the db.
        """

        for domain, active_checks, do_dns in self.get_domains():
            extra = []
            if not active_checks:
                extra.append('active checks disabled')
            if not do_dns:
                extra.append('dns lookups disabled')
            if extra:
                extra_str = ' ({})'.format(', '.join(extra))
            else:
                extra_str = ''
            print(f'{domain}{extra_str}')

    def show_domain(self, domain, show_raw=False):
        """
        Outputs information about the specified `domain` to the console.
        """

        # Get the domain record itself (if we can)
        self.cur.execute('select * from domain where domain=%s', (domain,))
        domainrow = self.cur.fetchone()
        if not domainrow:
            print(f'ERROR: {domain} is not found in our database')
            return
        if domainrow['active_checks'] == 0:
            extra = ' (active checks disabled)'
        else:
            extra = ''
        report_str = f'{domain}{extra}'
        print(report_str)
        print('='*len(report_str))

        # Get the *first* checked timestamp
        self.cur.execute("""
            select check_time from state
            where domain=%s
            order by check_time
            limit 1
            """, (domain,))
        firstrow = self.cur.fetchone()
        if firstrow:
            print('First checked: {}'.format(firstrow['check_time']))
        if domainrow['last_checked']:
            print('Last checked: {}'.format(domainrow['last_checked']))

        # Show the current state, if we have one
        if domainrow['last_state'] is None:
            print('No current state data!')
        else:
            # The "23" here is hardcoded; could instead do a max([len(s) for s in self.datapoints.values()])
            self.cur.execute('select * from state where id=%s', (domainrow['last_state'],))
            staterow = self.cur.fetchone()
            print('')
            print('  {:>23}: {}'.format(
                'State Since',
                staterow['check_time'],
                ))
            for key, eng in self.datapoints.items():
                print('  {:>23}: {}'.format(
                    eng,
                    staterow[key],
                    ))
        print('')

        # Show the raw info, if we've been asked to
        if show_raw:
            print('Raw Whois Data')
            print('--------------')
            print('')
            print(domainrow['cur_raw_text'])
            print('')

        # Historical info -- get a list of past states
        states = self._get_state_ids(domain)

        # Show history, if we have any (if we only have a single state, that
        # should be our first, so there won't be any changes)
        if len(states) < 2:
            print('(No history to show)')
            print('')
        else:
            for state_id, check_time in states:
                self.cur.execute("""
                    select * from changed
                    where state=%s
                    order by id
                    """, (state_id,))
                shown_header = False
                for row in self.cur:
                    if not shown_header:
                        header_line = f'Changes at {check_time}'
                        print(header_line)
                        print('-'*len(header_line))
                        shown_header = True
                    print(' - {}: {} -> {}'.format(
                        row['info'],
                        row['val_from'],
                        row['val_to'],
                        ))
                if shown_header:
                    print('')

def main():

    app_name_full = f"Python whois/DNS History v{__version__}"

    parser = argparse.ArgumentParser(
            description=app_name_full,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            epilog="""This app will create a sample config file (which contains
                database connection information) if one isn't found, and give
                you the file path so you can fill in the connection info.  Once
                connected to the database, it will create the schema if it's not
                already found.  So, to bootstrap the app, just run once, edit
                the config file, and then run it once more (probably while adding
                a new domain) to set up the schema.""",
            )

    parser.add_argument('-q', '--quiet',
            action='store_true',
            help="Only show output on errors, or if changes are detected",
            )

    # If we leave this out, we can at least let the user create the DB schema
    # without having to specify any specific options.
    actiongroup = parser.add_mutually_exclusive_group(required=False)

    actiongroup.add_argument('-d', '--domain',
            type=str,
            help="Domain to check (will add to database if not present)",
            )

    actiongroup.add_argument('-a', '--all',
            action='store_true',
            help="Check all known domains",
            )

    actiongroup.add_argument('-i', '--info',
            type=str,
            metavar='DOMAIN',
            help="Show historic information about the specified domain",
            )

    actiongroup.add_argument('-l', '--list',
            action='store_true',
            help="List all known domains",
            )

    actiongroup.add_argument('--activate',
            type=str,
            metavar='DOMAIN',
            help="""Ensure the specified domain is being actively checked
                (this is the default for newly-added domains)""",
            )

    actiongroup.add_argument('--deactivate',
            type=str,
            metavar='DOMAIN',
            help="""Ensure that the specified domain is NOT being actively
                checked""",
            )

    actiongroup.add_argument('--purge',
            type=str,
            metavar='DOMAIN',
            help="Purge specified domain from database",
            )

    actiongroup.add_argument('--wipe-database',
            action='store_true',
            help="Wipe the database.  Use with caution!",
            )

    actiongroup.add_argument('-v', '--version',
            action='store_true',
            help="Show app version",
            )

    parser.add_argument('-f', '--from-file',
            type=str,
            help="""Filename to use for pretend whois data
                (to avoid network calls while testing).  Only has
                an effect when used with -d/--domain.
                """,
            )

    dnsgroup = parser.add_mutually_exclusive_group()

    dnsgroup.add_argument('--dns',
            action='store_true',
            help="""Store DNS data when doing whois lookups, even if the
                domain is configured to not do so.  Will reconfigure the
                domain to do DNS checks on future runs.""",
            )

    dnsgroup.add_argument('--no-dns',
            action='store_true',
            help="""Do not store DNS data when doing whois lookups, even if
                the domain is configured to do so.  Will reconfigure the
                domain to not to DNS checks on future runs.""",
            )

    parser.add_argument('-s', '--secs',
            type=int,
            default=30,
            help="""Seconds to wait inbetween each domain, when using
                -a/--all (has no effect with other options)""",
            )

    parser.add_argument('-r', '--retries',
            type=int,
            default=3,
            help="""Number of times to retry a whois lookup, in the event
                of failure.  Will wait -s/--secs seconds inbetween each
                retry.""",
            )

    parser.add_argument('-w', '--whois',
            action='store_true',
            help="""When showing domain information, include the full,
                raw whois output.  (Has no effect with other options.)""",
            )

    args = parser.parse_args()

    # A bit of arg massaging for later
    status_domain = None
    status_domain_to = None
    if args.activate:
        status_domain = args.activate
        status_domain_to = True
    elif args.deactivate:
        status_domain = args.deactivate
        status_domain_to = False

    # ... a bit more
    if args.dns:
        dns_behavior = DNSBehavior.FORCE_YES
    elif args.no_dns:
        dns_behavior = DNSBehavior.FORCE_NO
    else:
        dns_behavior = DNSBehavior.DOMAIN_DEFAULT

    # If we've just been told to show the version, do that and exit
    # (so we don't instantiate an App object, which would potentially
    # create our config file or DB schema
    if args.version:
        print(app_name_full)
        sys.exit(0)

    # Set up the App object
    app = App(dns_behavior, args.secs, args.retries, not args.quiet)

    # Now do what we were told
    got_changes = False
    if args.wipe_database:
        app.wipe_db()
    elif args.domain:
        check_data = None
        if args.from_file:
            with open(args.from_file) as df:
                check_data = df.read()
        got_changes = app.check_domain(args.domain, check_data)
    elif args.all:
        got_changes = app.check_all_domains()
    elif args.info:
        app.show_domain(args.info, args.whois)
    elif args.list:
        app.show_domains()
    elif args.purge:
        app.purge_domain(args.purge)
    elif status_domain:
        app.set_domain_status(status_domain, status_domain_to)

    # Exit
    if got_changes:
        app.exit(2)
    else:
        app.exit(0)

if __name__ == '__main__':
    main()

