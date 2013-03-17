<?php

    
    function fourd_filter_var($string, $filter, $options) {
        return (string) filter_var($string,$filter,$options);
    }

    function fourd_filter_var_validate ($string, $filter, $options) {

        if (!filter_var($string,$filter,$options)) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Checks if a field is not empty.
     *
     * @return  boolean
     */
    function not_empty($value)
    {
        if (is_object($value) AND $value instanceof ArrayObject)
        {
            // Get the array from the ArrayObject
            $value = $value->getArrayCopy();
        }

        // Value cannot be NULL, FALSE, '', or an empty array
        return ! in_array($value, array(NULL, FALSE, '', array()), TRUE);
    }

    /**
     * Checks a field against a regular expression.
     *
     * @param   string  $value      value
     * @param   string  $expression regular expression to match (including delimiters)
     * @return  boolean
     */
    function regex($value, $expression)
    {
        return (bool) preg_match($expression, (string) $value);
    }

    /**
     * Checks that a field is long enough.
     *
     * @param   string  $value  value
     * @param   integer $length minimum length required
     * @return  boolean
     */
    function min_length($value, $length, $encodage="UTF-8")
    {
        return mb_strlen($value, $encodage) >= $length;
    }

    /**
     * Checks that a field is short enough.
     *
     * @param   string  $value  value
     * @param   integer $length maximum length required
     * @param   string  $encodage utilisé
     * @return  boolean
     */
    function max_length($value, $length, $encodage='UTF-8')
    {
        return mb_strlen($value, $encodage) <= $length;
    }

    /**
     * Checks that a field is exactly the right length.
     *
     * @param   string          $value  value
     * @param   integer|array   $length exact length required, or array of valid lengths
     * @return  boolean
     */
    function exact_length($value, $length)
    {
        if (is_array($length)) {

            foreach ($length as $strlen) {
                if (mb_strlen($value, 'UTF-8') === $strlen) {
                    return TRUE;
                }
            }
            return FALSE;
        }

        return (mb_strlen($value, 'UTF-8')) === $length;
    }

    /**
     * Checks that a field is exactly the value required.
     *
     * @param   string  $value      value
     * @param   string  $required   required value
     * @return  boolean
     */
    function equals($value, $required)
    {
        return ($value === $required);
    }

    /**
     * Check an email address for correct format.
     *
     * @link  http://www.iamcal.com/publish/articles/php/parsing_email/
     * @link  http://www.w3.org/Protocols/rfc822/
     *
     * @param   string  $email  email address
     * @param   boolean $strict strict RFC compatibility
     * @return  boolean
     */
    function email($email)
    {
        if (email_domain($email)) {
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return false;
            } else {
                return true;
            }
        } else {
            return false;
        }
    }

    /**
     * Validate the domain of an email address by checking if the domain has a
     * valid MX record.
     *
     * NOTE - This function will always return `TRUE` if the checkdnsrr() function
     * isn't avaliable (All Windows platforms before php 5.3)
     *
     * Usage:
     *
     *     $email = 'bill@gates.com';
     *     Validate::email_domain($email);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $email  Email address
     * @return  boolean          False if the domain is invalid, otherwise True. Always returns true if checkdnsrr() doesn't exist.
     */
    function email_domain($email)
    {
        // If we can't prove the domain is invalid, consider it valid
        // Note: checkdnsrr() is not implemented on Windows platforms
        //if (!function_exists('checkdnsrr'))
        //    return FALSE;

        // Check if the email domain has a valid MX record
        return (bool) checkdnsrr(preg_replace('/^[^@]+@/', '', $email), 'MX');
    }

    /**
     * RFC compliant email validation. This function is __LESS__ strict than
     * [Validate::email]. Choose carefully.
     *
     * Usage:
     *
     *     $email = 'bill@gates.com';
     *
     *     Validate::email_rfc($email);
     *
     *     // Output:
     *     (boolean) true
     *
     * @see  Originally by Cal Henderson but modified.
     * @see  http://www.iamcal.com/publish/articles/php/parsing_email/
     * @see  http://www.w3.org/Protocols/rfc822/
     *
     * @param   string   $email  Email address
     * @return  boolean
     */
    function email_rfc($email)
    {
        $qtext = '[^\\x0d\\x22\\x5c\\x80-\\xff]';
        $dtext = '[^\\x0d\\x5b-\\x5d\\x80-\\xff]';
        $atom = '[^\\x00-\\x20\\x22\\x28\\x29\\x2c\\x2e\\x3a-\\x3c\\x3e\\x40\\x5b-\\x5d\\x7f-\\xff]+';
        $pair = '\\x5c[\\x00-\\x7f]';

        $domain_literal = "\\x5b($dtext|$pair)*\\x5d";
        $quoted_string = "\\x22($qtext|$pair)*\\x22";
        $sub_domain = "($atom|$domain_literal)";
        $word = "($atom|$quoted_string)";
        $domain = "$sub_domain(\\x2e$sub_domain)*";
        $local_part = "$word(\\x2e$word)*";
        $addr_spec = "$local_part\\x40$domain";

        return (bool) preg_match('/^'.$addr_spec.'$/D', (string) $email);
    }



    /**
     * Basic URL validation.
     *
     * Usage:
     *
     *     $url = 'http://www.wolfcms.org';
     *
     *     Validate::url($url);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string  $url URL
     * @return  boolean
     */
    function url($url)
    {
        return (bool) filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_HOST_REQUIRED);
    }

    /**
     * validation d'un booleen
     * @param    mult
     * @return   boolean
     */
    function isBoolean ($vparam)
    {
        $result = filter_var($vparam, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

        if (is_null($result)) {
            return false;
        } else {
            return true;
        }

    }

    /**
     * Validates an IP Address.
     *
     * This only tests to see if the ip address is valid, it doesn't check to
     * see if the ip address is actually in use. Has optional support for
     * IPv6, and private ip address ranges.
     *
     * Usage:
     *
     *     $ip_address = '127.0.0.1';
     *
     *     Validate::ip($ip_address);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $ip             IP address
     * @param   boolean  $ipv6           Allow IPv6 addresses
     * @param   boolean  $allow_private  Allow private IP networks
     * @return  boolean
     */
    function ip($ip, $ipv6 = FALSE, $allow_private = TRUE)
    {
        // By default do not allow private and reserved range IPs
        $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        if ($allow_private === TRUE)
            $flags = FILTER_FLAG_NO_RES_RANGE;

        if ($ipv6 === TRUE)
            return (bool) filter_var($ip, FILTER_VALIDATE_IP, $flags);

        return (bool) filter_var($ip, FILTER_VALIDATE_IP, $flags | FILTER_FLAG_IPV4);

    }

    /**
     * Validates an private IP Address.
     * RFC http://tools.ietf.org/html/rfc1918
     *
     * @param   string  $ip          IP address
     * @return  boolean
     */
    function private_ip($ip)
    {
        /* http://tools.ietf.org/html/rfc1918 */
        return (bool) (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE));
    }

    /*
     * @desc validate uuid
     * @param string $uuid
     * @return booleen true if is valid
     */
    function uuid($uuid)
    {
        return preg_match('/^\{?[0-9a-f]{8}\-?[0-9a-f]{4}\-?[0-9a-f]{4}\-?'.
                '[0-9a-f]{4}\-?[0-9a-f]{12}\}?$/i', $uuid) === 1;
    }

    /**
     * Validates a credit card number using the [Luhn (mod10)](http://en.wikipedia.org/wiki/Luhn_algorithm)
     * formula.
     *
     * Usage:
     *
     *     // This is the standard Visa/Mastercard/AMEX test credit card number...
     *     $cc_number = '4111111111111111';
     *
     *     Validate::credit_card($cc_num, array('visa', 'mastercard'));
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   integer       $number  Credit card number
     * @param   string|array  $type    Card type, or an array of card types
     * @return  boolean
     */
    function credit_card($number, $type = NULL)
    {
        // Remove all non-digit characters from the number
        if (($number = preg_replace('/\D+/', '', $number)) === '')
            return FALSE;

        if ($type == NULL) {
            // Use the default type
            $type = 'default';
        } elseif (is_array($type)) {
            foreach ($type as $t) {
                // Test each type for validity
                if (self::credit_card($number, $t))
                    return TRUE;
            }

            return FALSE;
        }

        // Credit card check definitions
        $cards = array(
            'default' => array(
                'length' => '13,14,15,16,17,18,19',
                'prefix' => '',
                'luhn' => true
            ),
            'american express' => array(
                'length' => '15',
                'prefix' => '3[47]',
                'luhn' => true
            ),
            'diners club' => array(
                'length' => '14,16',
                'prefix' => '36|55|30[0-5]',
                'luhn' => true
            ),
            'discover' => array(
                'length' => '16',
                'prefix' => '6(?:5|011)',
                'luhn' => true,
            ),
            'jcb' => array(
                'length' => '15,16',
                'prefix' => '3|1800|2131',
                'luhn' => true
            ),
            'maestro' => array(
                'length' => '16,18',
                'prefix' => '50(?:20|38)|6(?:304|759)',
                'luhn' => true
            ),
            'mastercard' => array(
                'length' => '16',
                'prefix' => '5[1-5]',
                'luhn' => true
            ),
            'visa' => array(
                'length' => '13,16',
                'prefix' => '4',
                'luhn' => true
            ),
        );

        // Check card type
        $type = strtolower($type);

        if (!isset($cards[$type]))
            return FALSE;

        // Check card number length
        $length = strlen($number);

        // Validate the card length by the card type
        if (!in_array($length, preg_split('/\D+/', $cards[$type]['length'])))
            return FALSE;

        // Check card number prefix
        if (!preg_match('/^'.$cards[$type]['prefix'].'/', $number))
            return FALSE;

        // No Luhn check required
        if ($cards[$type]['luhn'] == FALSE)
            return TRUE;

        // Checksum of the card number
        $checksum = 0;

        for ($i = $length - 1; $i >= 0; $i -= 2) {
            // Add up every 2nd digit, starting from the right
            $checksum += substr($number, $i, 1);
        }

        for ($i = $length - 2; $i >= 0; $i -= 2) {
            // Add up every 2nd digit doubled, starting from the right
            $double = substr($number, $i, 1) * 2;

            // Subtract 9 from the double where value is greater than 10
            $checksum += ( $double >= 10) ? $double - 9 : $double;
        }

        // If the checksum is a multiple of 10, the number is valid
        return ($checksum % 10 === 0);
    }

    /**
     * Checks if a phone number is valid. This function will strip all non-digit
     * characters from the phone number for testing.
     *
     * Usage:
     *
     *     $phone_number = '(201) 664-0274';
     *
     *     Validate::phone($phone_number);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $number   Phone number to check
     * @param   array    $lengths  Valid lengths
     * @return  boolean
     */
    function phone($number, $lengths = NULL)
    {

        if (!is_array($lengths)) {
            $lengths = array(7, 10, 11);
        }

        // Remove all non-digit characters from the number
        $number = preg_replace('/\D+/', '', $number);

        // Check if the number is within range
        return in_array(strlen($number), $lengths);

    }

    /**
     * Tests if a string is a valid date using the php
     * [strtotime()](http://php.net/strtotime) function.
     *
     * Usage:
     *
     *     $date = '12/12/12';
     *
     *     Validate::date($date);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str  Date to check
     * @return  boolean
     */
    function validate_date($str)
    {
        return (strtotime($str) !== FALSE);
    }

    /**
     * Tests if a string conforms to a MySQL datetime format.
     *
     * This function does NOT test if the date is valid, just that the format is
     * valid.
     *
     * Usage:
     *
     *      $date = '2010-01-01 22:01:01';
     *
     *      Validate::datetime($date);
     *
     *      // Output:
     *      (boolean) true
     *
     * @param   string  $str    Datetime to check
     * @return  boolean         True if a valid datetime format, otherwise false.
     */
    function datetime($str)
    {
        return (bool) preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}$/D', (string) $str);
    }

    /**
     * Checks whether a string consists of alphabetical characters only.
     *
     * Usage:
     *
     *     $str = 'abcdefghijklmnopqrstuvwxyz';
     *
     *     Validate::alpha($str);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str   Input string
     * @param   boolean  $utf8  Trigger UTF-8 compatibility
     * @return  boolean
     */
    function alpha($str, $utf8 = FALSE) {
        return ($utf8 === TRUE) ? (bool) preg_match('/^\pL++$/uD', (string) $str) : ctype_alpha((string) $str);
    }

    /**
     * Checks whether a string consists of alphabetical characters and numbers only.
     *
     * Usage:
     *
     *     $str = 'abcdefghijklmnopqrstuvwxyz1234567890*****';
     *
     *     Validate::alpha_numeric($str);
     *
     *     // Output:
     *     (boolean) false
     *
     * @param   string   $str   Input string
     * @param   boolean  $utf8  Trigger UTF-8 compatibility
     * @return  boolean
     */
    function alpha_numeric($str, $utf8 = FALSE)
    {
        return ($utf8 === TRUE) ? (bool) preg_match('/^[\pL\pN]++$/uD', (string) $str) : ctype_alnum((string) $str);
    }

    /**
     * Checks whether a string consists of alphabetical characters, numbers,
     * underscores and dashes only.
     *
     * Usage:
     *
     *     $str = 'abcdefghijklmnopqrstuvwxyz_-ABC123';
     *
     *     Validate::alpha_dash($str);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str  Input string
     * @param   boolean  $utf8  Trigger UTF-8 compatibility
     * @return  boolean
     */
    function alpha_dash($str, $utf8 = FALSE)
    {
        return ($utf8 === TRUE) ? (bool) preg_match('/^[-\pL\pN_]++$/uD', (string) $str) : (bool) preg_match('/^[-a-z0-9_]++$/iD', (string) $str);
    }

    /**
     * Checks whether a string consists of alphabetical characters, numbers,
     * underscores, commas, spaces and dashes only.
     *
     * Usage:
     *
     *     $str = 'abcdefghijklmnopqrstuvwxyz_-, ABC123';
     *
     *     Validate::alpha_comma($str);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str  Input string
     * @param   boolean  $utf8  Trigger UTF-8 compatibility
     * @return  boolean
     */
    function alpha_comma($str, $utf8 = FALSE)
    {
        return ($utf8 === TRUE) ? (bool) preg_match('/^[-\pL\pN_, .]++$/uD', (string) $str) : (bool) preg_match('/^[-a-z0-9_, .]++$/iD', (string) $str);
    }

    /**
     * Checks whether a string consists of alphabetical characters, numbers,
     * underscores, commas, spaces, dashes and / only .
     *
     * Usage:
     *
     *     $str = 'abcdefghijklmnopqrstuvwxyz_-/, ABC123';
     *
     *     Validate::alpha_comma($str);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str  Input string
     * @param   boolean  $utf8  Trigger UTF-8 compatibility
     * @return  boolean
     */
    function alpha_path($str, $utf8 = FALSE) {
        return ($utf8 === TRUE) ? (bool) preg_match('/^[-\pL\pN_\/, .]++$/uD', (string) $str) : (bool) preg_match('/^[-a-z0-9_\/, ]++$/iD', (string) $str);
    }

    /**
     * Checks wheter a string is a valid slug.
     *
     * @param string $str Slug
     */
    function slug($str, $utf8 = FALSE)
    {
        return ($utf8 === TRUE) ? (bool) preg_match('/^[-\pLl\pN_]++$/uD', (string) $str) : (bool) preg_match('/^[-a-z0-9_]++$/D', (string) $str);
    }

    /**
     * Checks whether a string consists of alphabetical characters and spaces only.
     *
     * Usage:
     *
     *     $str = 'abc defghijkl mnopqrstuv wxyz';
     *
     *     Validate::alpha_space($str);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str  Input string
     * @param   boolean  $utf8  Trigger UTF-8 compatibility
     * @return  boolean
     */
    function alpha_space($str, $utf8 = FALSE)
    {
        return ($utf8 === TRUE) ? (bool) preg_match('/^[\pL\s]++$/uD', (string) $str) : (bool) preg_match('/^[a-z\s]++$/iD', (string) $str);
    }

    /**
     * Checks whether a string consists of alphanumerical characters and spaces only.
     *
     * Usage:
     *
     *     $str = 'abc defghijkl mnopqrstuv wxyz12312 34 ASD';
     *
     *     Validate::alphanum_space($str);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str  Input string
     * @param   boolean  $utf8  Trigger UTF-8 compatibility
     * @return  boolean
     */
    function alphanum_space($str, $utf8 = FALSE)
    {
        return ($utf8 === TRUE) ? (bool) preg_match('/^[\pL\pN\s]++$/uD', (string) $str) : (bool) preg_match('/^[a-z0-9\s]++$/iD', (string) $str);
    }

    /**
     * Checks whether a string consists of digits only (no dots or dashes).
     *
     * Usage:
     *
     *     $str = '23';
     *
     *     Validate::digit('23');
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str    Input string
     * @param   boolean  $utf8   Trigger UTF-8 compatibility
     * @return  boolean
     */
    function digit($str, $utf8 = FALSE)
    {
        return ($utf8 === TRUE) ? (bool) preg_match('/^\pN++$/uD', (string) $str) : ctype_digit((string) $str);
    }

    /**
     * Checks whether a string is a valid number (negative and decimal numbers allowed).
     * This function uses [localeconv()](http://www.php.net/manual/en/function.localeconv.php)
     * to support international number formats.
     *
     * Usage:
     *
     *     Validate::numeric('2.3');
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str  Input string
     * @return  boolean
     */
    function numeric($str)
    {
        // Use localeconv to set the decimal_point value: Usually a comma or period.
        $locale = localeconv();
        return (bool) preg_match('/^-?[0-9'.$locale['decimal_point'].']++$/D', (string) $str);
    }

    /**
     * Tests if an integer is within a range.
     *
     * Usage:
     *
     *     $num = '5';
     *
     *     Validate::range('5', array(1, 10));
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   integer  $number  Number to check
     * @param   array    $range   Valid range of input
     * @return  boolean
     */
    function validate_range($number, array $range)
    {
        // Invalid by default
        $status = FALSE;

        if (is_int($number) OR ctype_digit($number)) {
            if (count($range) > 1) {
                if ($number >= $range[0] AND $number <= $range[1]) {
                    // Number is within the required range
                    $status = TRUE;
                }
            }
            elseif ($number >= $range[0]) {
                // Number is greater than the minimum
                $status = TRUE;
            }
        }

        return $status;
    }

    /**
     * Checks if a string is a proper decimal format. The format array can be
     * used to specify a decimal length, or a number and decimal length, eg:
     * array(2) would force the number to have 2 decimal places, array(4,2)
     * would force the number to have 4 digits and 2 decimal places.
     *
     * Usage:
     *
     *     Validate::decimal('4.5', array(2,1));
     *
     *     // Output:
     *     (boolean) false
     *
     * @param   string   $str     Input string
     * @param   array    $format  Decimal format: y or x,y
     * @return  boolean
     */
    function decimal($str, $format = NULL)
    {
        // Create the pattern
        $pattern = '/^[0-9]%s\.[0-9]%s$/';

        if (!empty($format)) {
            if (count($format) > 1) {
                // Use the format for number and decimal length
                $pattern = sprintf($pattern, '{'.$format[0].'}', '{'.$format[1].'}');
            }
            elseif (count($format) > 0) {
                // Use the format as decimal length
                $pattern = sprintf($pattern, '+', '{'.$format[0].'}');
            }
        }
        else {
            // No format
            $pattern = sprintf($pattern, '+', '+');
        }

        return (bool) preg_match($pattern, (string) $str);
    }

    /**
     * Checks if a string is a proper hexadecimal HTML color value. The validation
     * is quite flexible as it does not require an initial "#" and also allows for
     * the short notation using only three instead of six hexadecimal characters.
     *
     * Usage:
     *
     *     Validate::color('#CCCCCC');
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   string   $str  Input string
     * @return  boolean
     */
    function color($str)
    {
        return (bool) preg_match('/^#?+[0-9a-f]{3}(?:[0-9a-f]{3})?$/iD', $str);
    }

    /**
     * Performs a simple test using the modulo operator to see if a given
     * divisor is a multiple of the given dividend.
     *
     * Usage:
     *
     *     Validate::multiple(200, 50);
     *
     *     // Output:
     *     (boolean) true
     *
     * @param   integer   $dividend  Dividend
     * @param   integer   $divisor  Divisor
     * @return  boolean
     */
    function multiple($dividend, $divisor)
    {
        // Note: this needs to be reversed because modulo returns a zero remainder for a true multiple
        return!(bool) ((int) $dividend % (int) $divisor);
    }

    function postcode($postcode, $territory='nl')
    {
        if (!is_string($postcode) && !is_int($postcode)) {
            return false;
        }

        // Known postal codes for various territories.
        // See http://www.iso.org/iso/english_country_names_and_code_elements for territory codes
        $formats = array(
            'gb' => 'GIR[ ]?0AA|((AB|AL|B|BA|BB|BD|BH|BL|BN|BR|BS|BT|CA|CB|CF|CH|CM|CO|CR|CT|CV|CW|DA|DD|DE|DG|DH|DL|DN|DT|DY|E|EC|EH|EN|EX|FK|FY|G|GL|GY|GU|HA|HD|HG|HP|HR|HS|HU|HX|IG|IM|IP|IV|JE|KA|KT|KW|KY|L|LA|LD|LE|LL|LN|LS|LU|M|ME|MK|ML|N|NE|NG|NN|NP|NR|NW|OL|OX|PA|PE|PH|PL|PO|PR|RG|RH|RM|S|SA|SE|SG|SK|SL|SM|SN|SO|SP|SR|SS|ST|SW|SY|TA|TD|TF|TN|TQ|TR|TS|TW|UB|W|WA|WC|WD|WF|WN|WR|WS|WV|YO|ZE)(\d[\dA-Z]?[]?\d[ABD-HJLN-UW-Z]{2}))|BFPO[ ]?\d{1,4}',
            'je' => 'JE\d[\dA-Z]?[ ]?\d[ABD-HJLN-UW-Z]{2}',
            'gg' => 'GY\d[\dA-Z]?[ ]?\d[ABD-HJLN-UW-Z]{2}',
            'im' => 'IM\d[\dA-Z]?[ ]?\d[ABD-HJLN-UW-Z]{2}',
            'us' => '\d{5}([ \-]\d{4})?',
            'ca' => '[ABCEGHJKLMNPRSTVXY]\d[A-Z][ ]?\d[A-Z]\d',
            'de' => '\d{5}',
            'jp' => '\d{3}-\d{4}',
            'fr' => '\d{2}[ ]?\d{3}',
            'au' => '\d{4}',
            'it' => '\d{5}',
            'ch' => '\d{4}',
            'at' => '\d{4}',
            'es' => '\d{5}',
            'nl' => '\d{4}[ ]?[A-Z]{2}',
            'be' => '\d{4}',
            'dk' => '\d{4}',
            'se' => '\d{3}[ ]?\d{2}',
            'no' => '\d{4}',
            'br' => '\d{5}[\-]?\d{3}',
            'pt' => '\d{4}([\-]\d{3})?',
            'fi' => '\d{5}',
            'ax' => '22\d{3}',
            'kr' => '\d{3}[\-]\d{3}',
            'cn' => '\d{6}',
            'tw' => '\d{3}(\d{2})?',
            'sg' => '\d{6}',
            'dz' => '\d{5}',
            'ad' => 'AD\d{3}',
            'ar' => '([A-HJ-NP-Z])?\d{4}([A-Z]{3})?',
            'am' => '(37)?\d{4}',
            'az' => '\d{4}',
            'bh' => '((1[0-2]|[2-9])\d{2})?',
            'bd' => '\d{4}',
            'bb' => '(BB\d{5})?',
            'by' => '\d{6}',
            'bm' => '[A-Z]{2}[ ]?[A-Z0-9]{2}',
            'ba' => '\d{5}',
            'io' => 'BBND 1ZZ',
            'bn' => '[A-Z]{2}[ ]?\d{4}',
            'bg' => '\d{4}',
            'kh' => '\d{5}',
            'cv' => '\d{4}',
            'cl' => '\d{7}',
            'cr' => '\d{4,5}|\d{3}-\d{4}',
            'hr' => '\d{5}',
            'cy' => '\d{4}',
            'cz' => '\d{3}[ ]?\d{2}',
            'do' => '\d{5}',
            'ec' => '([A-Z]\d{4}[A-Z]|(?:[A-Z]{2})?\d{6})?',
            'eg' => '\d{5}',
            'ee' => '\d{5}',
            'fo' => '\d{3}',
            'ge' => '\d{4}',
            'gr' => '\d{3}[ ]?\d{2}',
            'gl' => '39\d{2}',
            'gt' => '\d{5}',
            'ht' => '\d{4}',
            'hn' => '(?:\d{5})?',
            'hu' => '\d{4}',
            'is' => '\d{3}',
            'in' => '\d{6}',
            'id' => '\d{5}',
            'ie' => '((D|DUBLIN)?([1-9]|6[wW]|1[0-8]|2[024]))?',
            'il' => '\d{5}',
            'jo' => '\d{5}',
            'kz' => '\d{6}',
            'ke' => '\d{5}',
            'kw' => '\d{5}',
            'la' => '\d{5}',
            'lv' => '\d{4}',
            'lb' => '(\d{4}([ ]?\d{4})?)?',
            'li' => '(948[5-9])|(949[0-7])',
            'lt' => '\d{5}',
            'lu' => '\d{4}',
            'mk' => '\d{4}',
            'my' => '\d{5}',
            'mv' => '\d{5}',
            'mt' => '[A-Z]{3}[ ]?\d{2,4}',
            'mu' => '(\d{3}[A-Z]{2}\d{3})?',
            'mx' => '\d{5}',
            'md' => '\d{4}',
            'mc' => '980\d{2}',
            'ma' => '\d{5}',
            'np' => '\d{5}',
            'nz' => '\d{4}',
            'ni' => '((\d{4}-)?\d{3}-\d{3}(-\d{1})?)?',
            'ng' => '(\d{6})?',
            'om' => '(PC )?\d{3}',
            'pk' => '\d{5}',
            'py' => '\d{4}',
            'ph' => '\d{4}',
            'pl' => '\d{2}-\d{3}',
            'pr' => '00[679]\d{2}([ \-]\d{4})?',
            'ro' => '\d{6}',
            'ru' => '\d{6}',
            'sm' => '4789\d',
            'sa' => '\d{5}',
            'sn' => '\d{5}',
            'sk' => '\d{3}[ ]?\d{2}',
            'si' => '\d{4}',
            'za' => '\d{4}',
            'lk' => '\d{5}',
            'tj' => '\d{6}',
            'th' => '\d{5}',
            'tn' => '\d{4}',
            'tr' => '\d{5}',
            'tm' => '\d{6}',
            'ua' => '\d{5}',
            'uy' => '\d{5}',
            'uz' => '\d{6}',
            'va' => '00120',
            've' => '\d{4}',
            'zm' => '\d{5}',
            'as' => '96799',
            'cc' => '6799',
            'ck' => '\d{4}',
            'rs' => '\d{6}',
            'me' => '8\d{4}',
            'cs' => '\d{5}',
            'yu' => '\d{5}',
            'cx' => '6798',
            'et' => '\d{4}',
            'fk' => 'FIQQ 1ZZ',
            'nf' => '2899',
            'fm' => '(9694[1-4])([ \-]\d{4})?',
            'gf' => '9[78]3\d{2}',
            'gn' => '\d{3}',
            'gp' => '9[78][01]\d{2}',
            'gs' => 'SIQQ 1ZZ',
            'gu' => '969[123]\d([ \-]\d{4})?',
            'gw' => '\d{4}',
            'hm' => '\d{4}',
            'iq' => '\d{5}',
            'kg' => '\d{6}',
            'lr' => '\d{4}',
            'ls' => '\d{3}',
            'mg' => '\d{3}',
            'mh' => '969[67]\d([ \-]\d{4})?',
            'mn' => '\d{6}',
            'mp' => '9695[012]([ \-]\d{4})?',
            'mq' => '9[78]2\d{2}',
            'nc' => '988\d{2}',
            'ne' => '\d{4}',
            'vi' => '008(([0-4]\d)|(5[01]))([ \-]\d{4})?',
            'pf' => '987\d{2}',
            'pg' => '\d{3}',
            'pm' => '9[78]5\d{2}',
            'pn' => 'PCRN 1ZZ',
            'pw' => '96940',
            're' => '9[78]4\d{2}',
            'sh' => 'STHL 1ZZ',
            'sj' => '\d{4}',
            'so' => '\d{5}',
            'sz' => '[HLMS]\d{3}',
            'tc' => 'TKCA 1ZZ',
            'wf' => '986\d{2}',
            'yt' => '976\d{2}'
        );

        if (!preg_match('/'.$formats[$territory].'/', $postcode)) {
            return false;
        }

        return true;
    }

    /**
     * Tests a string as to whether it's valid UTF-8 and supported by the
     * Unicode standard.
     *
     * This code has been taken from the phputf8 library.
     *
     * @author <hsivonen@iki.fi>
     * @see http://hsivonen.iki.fi/php-utf8/
     *
     * @param string UTF-8 encoded string
     * @return boolean true if valid
     */
    function valid_utf8($str)
    {

        $mState = 0;     // cached expected number of octets after the current octet
                         // until the beginning of the next UTF8 character sequence
        $mUcs4  = 0;     // cached Unicode character
        $mBytes = 1;     // cached expected number of octets in the current sequence

        $len = strlen($str);

        for ($i = 0; $i < $len; $i++) {

            $in = ord($str{$i});

            if ($mState == 0) {

                // When mState is zero we expect either a US-ASCII character or a
                // multi-octet sequence.
                if (0 == (0x80 & ($in))) {
                    // US-ASCII, pass straight through.
                    $mBytes = 1;
                }
                else if (0xC0 == (0xE0 & ($in))) {
                    // First octet of 2 octet sequence
                    $mUcs4 = ($in);
                    $mUcs4 = ($mUcs4 & 0x1F) << 6;
                    $mState = 1;
                    $mBytes = 2;
                }
                else if (0xE0 == (0xF0 & ($in))) {
                    // First octet of 3 octet sequence
                    $mUcs4 = ($in);
                    $mUcs4 = ($mUcs4 & 0x0F) << 12;
                    $mState = 2;
                    $mBytes = 3;
                }
                else if (0xF0 == (0xF8 & ($in))) {
                    // First octet of 4 octet sequence
                    $mUcs4 = ($in);
                    $mUcs4 = ($mUcs4 & 0x07) << 18;
                    $mState = 3;
                    $mBytes = 4;
                }
                else if (0xF8 == (0xFC & ($in))) {
                    /* First octet of 5 octet sequence.
                     *
                     * This is illegal because the encoded codepoint must be either
                     * (a) not the shortest form or
                     * (b) outside the Unicode range of 0-0x10FFFF.
                     * Rather than trying to resynchronize, we will carry on until the end
                     * of the sequence and let the later error handling code catch it.
                     */
                    $mUcs4 = ($in);
                    $mUcs4 = ($mUcs4 & 0x03) << 24;
                    $mState = 4;
                    $mBytes = 5;
                }
                else if (0xFC == (0xFE & ($in))) {
                    // First octet of 6 octet sequence, see comments for 5 octet sequence.
                    $mUcs4 = ($in);
                    $mUcs4 = ($mUcs4 & 1) << 30;
                    $mState = 5;
                    $mBytes = 6;
                }
                else {
                    /* Current octet is neither in the US-ASCII range nor a legal first
                     * octet of a multi-octet sequence.
                     */
                    return FALSE;
                }
            }
            else {

                // When mState is non-zero, we expect a continuation of the multi-octet
                // sequence
                if (0x80 == (0xC0 & ($in))) {

                    // Legal continuation.
                    $shift = ($mState - 1) * 6;
                    $tmp = $in;
                    $tmp = ($tmp & 0x0000003F) << $shift;
                    $mUcs4 |= $tmp;

                    /**
                     * End of the multi-octet sequence. mUcs4 now contains the final
                     * Unicode codepoint to be output
                     */
                    if (0 == --$mState) {

                        /*
                         * Check for illegal sequences and codepoints.
                         */
                        // From Unicode 3.1, non-shortest form is illegal
                        if (((2 == $mBytes) && ($mUcs4 < 0x0080)) ||
                                ((3 == $mBytes) && ($mUcs4 < 0x0800)) ||
                                ((4 == $mBytes) && ($mUcs4 < 0x10000)) ||
                                (4 < $mBytes) ||
                                // From Unicode 3.2, surrogate characters are illegal
                                (($mUcs4 & 0xFFFFF800) == 0xD800) ||
                                // Codepoints outside the Unicode range are illegal
                                ($mUcs4 > 0x10FFFF)) {

                            return FALSE;
                        }

                        //initialize UTF8 cache
                        $mState = 0;
                        $mUcs4 = 0;
                        $mBytes = 1;
                    }
                }
                else {
                    /**
                     * ((0xC0 & (*in) != 0x80) && (mState != 0))
                     * Incomplete multi-octet sequence.
                     */
                    return FALSE;
                }
            }
        }
        return TRUE;
    }

    /**
     * Tests whether a string complies as UTF-8.
     *
     * This will be much faster than utf8_is_valid but will pass five and
     * six octet UTF-8 sequences, which are not supported by Unicode and
     * so cannot be displayed correctly in a browser. In other words
     * it is not as strict as utf8_is_valid but it's faster.
     *
     * If your use is to validate user input, you place yourself at the risk
     * that attackers will be able to inject 5 and 6 byte sequences (which
     * may or may not be a significant risk, depending on what you are
     * are doing)
     *
     * @see http://www.php.net/manual/en/reference.pcre.pattern.modifiers.php#54805
     *
     * @param string UTF-8 string to check
     * @return boolean TRUE if string is valid UTF-8
     */
    function compliant_utf8($str)
    {
        if (strlen($str) == 0) {
            return TRUE;
        }
        // If even just the first character can be matched, when the /u
        // modifier is used, then it's valid UTF-8. If the UTF-8 is somehow
        // invalid, nothing at all will match, even if the string contains
        // some valid sequences
        return (preg_match('/^.{1}/us', $str, $ar) == 1);
    }
