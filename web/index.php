<?php // vim: set expandtab tabstop=4 shiftwidth=4:

/**
 * Copyright 2022 Christopher J. Kucera
 * <cj@apocalyptech.com>
 * <http://apocalyptech.com/contact.php>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the development team nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CJ KUCERA BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// For debugging purposes
/*
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
*/

$app_version = 'pywhoishistory web frontend v1.0.1';

// Using PHP 7.x, so I guess no native PHP enums for me?
$TYPE_STR = 1;
$TYPE_LIST = 2;
$TYPE_DATETIME = 3;

$errors = array();
$date_fmt = 'l, F j, Y, G:i:s';
$state_reports = array(
    array('check_time', 'State Since', $TYPE_DATETIME),
    array('registrar', 'Registrar', $TYPE_STR),
    array('whois_server', 'WHOIS Server', $TYPE_STR),
    array('referral_url', 'Referral URL', $TYPE_STR),
    array('updated_date', 'Updated Date', $TYPE_STR),
    array('creation_date', 'Creation Date', $TYPE_STR),
    array('expiration_date', 'Expiration Date', $TYPE_STR),
    array('name_servers', 'Nameservers', $TYPE_LIST),
    array('status', 'Status', $TYPE_LIST),
    array('emails', 'Emails', $TYPE_LIST),
    array('dnssec', 'DNSSEC', $TYPE_STR),
    array('name', 'Registrant Name', $TYPE_STR),
    array('org', 'Registrant Organization', $TYPE_STR),
    array('address', 'Registrant Address', $TYPE_STR),
    array('city', 'Registrant City', $TYPE_STR),
    array('state', 'Registrant State', $TYPE_STR),
    array('zipcode', 'Registrant Zipcode', $TYPE_STR),
    array('ip', 'IP Address', $TYPE_LIST),
    array('mx', 'MX Addresses', $TYPE_LIST),
);

// Connect to the database
require_once('dbinfo.php');
$db = new mysqli($dbhost, $dbuser, $dbpass, $dbname, $dbport);
if ($db->connect_errno)
{
    print 'Error connecting to database: ' . $db->connect_error;
    exit;
}

// Doublecheck that our database is at the correct version.  If I ever bump
// up the DB ver, I'll have to see if it's worth it to make this web component
// backwards-compatible.  For now, I'll just require v1.
$stmt = $db->prepare('select value from param where param="db_ver"');
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();
if ($row['value'] != 1)
{
    print 'ERROR: Database version ' . $row['value'] . ' is not supported.';
    exit;
}
$result->close();
$stmt->close();

// Do some sanity checks on our $_REQUEST['d'], if we have it.  At the moment
// this is being real strict and is only allowing some basic ASCII chars in
// the domain.  This will be too restrictive for many use-cases.
$req_domain = null;
if (array_key_exists('d', $_REQUEST))
{
    if (preg_match('/^[-a-zA-Z0-9\.]+$/', $_REQUEST['d']))
    {
        $req_domain = $_REQUEST['d'];
    }
    else
    {
        $errors[] = 'Invalid domain specified';
    }
}

// Get a list of domains
$found_req_domain = false;
$domains = array();
$stmt = $db->prepare('select domain from domain order by domain');
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc())
{
    if ($req_domain == $row['domain'])
    {
        $found_req_domain = true;
    }
    $domains[] = $row['domain'];
}
$result->close();
$stmt->close();
if (!$found_req_domain)
{
    if ($req_domain !== null)
    {
        $errors[] = 'Domain not found';
        $req_domain = null;
    }
}

// Function to draw a dropdown
function dropdown($name, $options, $cur_val, $on_change=null)
{
    $html_name = htmlentities($name);
    print '<select name="' . $html_name . '" id="' . $html_name . '"';
    if ($on_change !== null)
    {
        print ' onChange="' . $on_change . '"';
    }
    print ">\n";
    print '<option value="">&nbsp;</option>' . "\n";
    foreach ($options as $option)
    {
        $html_option = htmlentities($option);
        print '<option value="' . $html_option . '"';
        if ($cur_val == $option)
        {
            print ' selected';
        }
        print '>' . $html_option . "</option>\n";
    }
    print "</select>\n";
}

// Function to output our "raw" whois data
function show_raw_data($text, $id, $time_label=false)
{
    print '<div class="link_button">' . "\n";
    print '<span class="show_raw_link" ';
    print 'id="show_raw_link_' . $id . '" ';
    print 'onClick="showRawData(\'' . $id . '\'); return false;">';
    if ($time_label)
    {
        print "(show raw whois data at this time)";
    }
    else
    {
        print "(show raw whois data)";
    }
    print "</span>\n";

    print '<span class="hide_raw_link" ';
    print 'id="hide_raw_link_' . $id . '" ';
    print 'onClick="hideRawData(\'' . $id . '\'); return false;">';
    if ($time_label)
    {
        print "(hide raw whois data at this time)";
    }
    else
    {
        print "(hide raw whois data)";
    }
    print "</span>\n";

    print "</div>\n";

    print '<pre class="raw_data" id="raw_data_' . $id . '">' . "\n";
    print htmlentities($text);
    print "</pre>\n";
}

// Stupid little class to encapsulate state data for us
class State
{
    public function __construct($row)
    {
        $this->id = $row['id'];
        $this->check_time = strtotime($row['check_time']);
        $this->raw_text = $row['raw_text'];
    }
}

?>
<!DOCTYPE html>
<html>
<head>
<title><?php echo $app_version; ?></title>
<script language="javascript" type="text/javascript" src="whois.js?v=1"></script>
<link rel="stylesheet" type="text/css" media="all" href="whois.css?v=1" />
</head>
<body>

<form method="GET" action="index.php" id="whoisform">
Choose a domain:<br />
<?php dropdown('d', $domains, $req_domain, 'return submitWhois();'); ?>
<input type="submit" value="Go">
<div class="version"><?php echo $app_version; ?></div>
</form>

<?php
// Okay, if we're here, see if we have a requested domain.  If so, start pullin' stuff from
// the database

if ($req_domain !== null)
{
    $domain_record = null;
    $stmt = $db->prepare('select * from domain where domain=?');
    $stmt->bind_param('s', $req_domain);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc())
    {
        $domain_record = $row;
    }
    else
    {
        // There really shouldn't be any way to get here -- we filter $req_domain
        // while reading the global domain list way up at the top.  Still...
        $errors[] = 'Could not find domain: ' . $req_domain;
    }
    $result->close();
    $stmt->close();

    if ($domain_record)
    {

        // Get a list of states for reporting.  We don't actually care about
        // the majority of the data in here, but we'll pull a few things out.
        $states = array();
        $stmt = $db->prepare('select id, check_time, raw_text from state where domain=? order by check_time asc');
        $stmt->bind_param('s', $req_domain);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc())
        {
            $states[] = new State($row);
        }
        $result->close();
        $stmt->close();

        // Get our "full" state data of the most recent state, too
        $cur_state = null;
        $stmt = $db->prepare('select * from state where id=?');
        $stmt->bind_param('i', $domain_record['last_state']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($row = $result->fetch_assoc())
        {
            $cur_state = $row;
        }
        else
        {
            $errors[] = 'Current state record not found';
        }
        $result->close();
        $stmt->close();

        // Now we start reporting in earnest
        print '<h1>Results for ' . htmlentities($req_domain) . "</h1>\n";
        print "<blockquote>\n";
        print '<p class="main_dates">' . "\n";
        print 'First checked: <i>' . date($date_fmt, $states[0]->check_time) . "</i><br />\n";
        print 'Last checked: <i>' . date($date_fmt, strtotime($domain_record['last_checked'])) . "</i>\n";
        print "</p>\n";

        if ($cur_state !== null)
        {
            print '<table class="domain_state">' . "\n";
            foreach ($state_reports as $state_report)
            {
                print "<tr>\n";
                print '<td class="state_label">' . htmlentities($state_report[1]) . ":</td>\n";
                print '<td class="state_value">';
                $state_value = $cur_state[$state_report[0]];
                switch ($state_report[2])
                {
                    case $TYPE_LIST:
                        // This might be a comma-separated list
                        $exploded = explode(', ', $state_value);
                        if (count($exploded) > 1)
                        {
                            print "<ul>\n";
                            foreach ($exploded as $item)
                            {
                                print '<li>' . htmlentities($item) . "</li>\n";
                            }
                            print "</ul>\n";
                        }
                        else
                        {
                            // ... or it might not.
                            print htmlentities($state_value);
                        }
                        break;

                    case $TYPE_DATETIME:
                        // Datetime!
                        print htmlentities(date($date_fmt, strtotime($state_value)));
                        break;
                    
                    default:
                    case $TYPE_STR:
                        // This should just be plaintext
                        print htmlentities($state_value);
                        break;

                }
                print "</td>\n";
                print "</tr>\n";
            }
            print "</table>\n";

            show_raw_data($domain_record['cur_raw_text'], 'cur_data');
        }

        // Show details about the historical changes
        $first = true;
        foreach ($states as $state)
        {
            if ($first)
            {
                print '<h2>Originally added at ' . date($date_fmt, $state->check_time) . "</h2>\n";
            }
            else
            {
                print '<h2>Changes at ' . date($date_fmt, $state->check_time) . "</h2>\n";
                print '<ul class="change_list">' . "\n";
                $stmt = $db->prepare('select * from changed where state=?');
                $stmt->bind_param('i', $state->id);
                $stmt->execute();
                $result = $stmt->get_result();
                while ($row = $result->fetch_assoc())
                {
                    print "<li>\n";
                    print '<b>' . htmlentities($row['info']) . ":</b>\n";
                    print "<ul>\n";
                    print '<li>From: <tt>' . htmlentities($row['val_from']) . "</tt></li>\n";
                    print '<li>To: <tt>' . htmlentities($row['val_to']) . "</tt></li>\n";
                    print "</ul>\n";
                    print "</li>\n";
                }
                $result->close();
                $stmt->close();
                print "</ul>\n";
            }

            show_raw_data($state->raw_text, $state->id, true);
            $first = false;
        }

        print "</blockquote>\n";

    }

}

// Show errors, if we have any.
if (count($errors) > 0)
{
    print '<div class="errors">' . "\n";
    print "<ul>\n";
    foreach ($errors as $error)
    {
        print '<li>' . htmlentities($error) . "</li>\n";
    }
    print "</ul>\n";
    print "</div>\n";
}

?>

</body>
</html>

