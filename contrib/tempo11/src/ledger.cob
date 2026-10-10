identification division.
program-id. tempo11-ledger.
environment division.
configuration section.
repository. function all intrinsic.
data division.
working-storage section.
01 input-line pic x(256).
01 command-name pic x(8).
01 number-text pic x(20).
01 block-number usage binary-double unsigned.
01 head-number usage binary-double unsigned.
01 block-hash pic x(64).
01 parent-hash pic x(64).
01 head-hash pic x(64).
01 has-head pic 9 value 0.
01 seen-input pic 9 value 0.
01 fields-count usage binary-long.
01 matches-count usage binary-long.
01 i usage binary-long.
01 hex-digits pic x(16) value '0123456789abcdef'.
procedure division.
    perform until command-name = 'QUIT'
        move spaces to input-line command-name number-text
            block-hash parent-hash
        accept input-line
        if input-line = spaces
            move 1 to return-code
            goback
        end-if
        if trim(input-line) = 'QUIT'
            display 'BYE'
            move 0 to return-code
            goback
        end-if
        move 0 to fields-count
        unstring trim(input-line) delimited by all space
            into command-name number-text block-hash parent-hash
            tallying in fields-count
            on overflow perform malformed-record
        end-unstring
        if fields-count not = 4 or number-text = spaces
            perform malformed-record
        end-if
        if trim(number-text) is not numeric
            perform malformed-record
        end-if
        *> SQLite's durable height uses signed 64-bit integers.
        if function numval(number-text) > 9223372036854775806
            perform malformed-record
        end-if
        compute block-number = function numval(number-text)
        perform varying i from 1 by 1 until i > 64
            move 0 to matches-count
            inspect hex-digits tallying matches-count
                for all block-hash(i:1)
            inspect hex-digits tallying matches-count
                for all parent-hash(i:1)
            if matches-count not = 2
                perform malformed-record
            end-if
        end-perform
        evaluate trim(command-name)
            when 'ANCHOR'
                if seen-input = 1 perform malformed-record end-if
            when 'BLOCK'
                if has-head = 1
                    if block-number not = head-number + 1
                        display 'ERROR NONCONTIGUOUS-HEIGHT'
                        move 1 to return-code
                        goback
                    end-if
                    if parent-hash not = head-hash
                        display 'ERROR PARENT-MISMATCH'
                        move 1 to return-code
                        goback
                    end-if
                else
                    if block-number not = 0
                        display 'ERROR MISSING-GENESIS'
                        move 1 to return-code
                        goback
                    end-if
                end-if
            when other
                perform malformed-record
        end-evaluate
        move 1 to seen-input has-head
        move block-number to head-number
        move block-hash to head-hash
        display 'OK ' trim(number-text) ' ' block-hash
    end-perform.
malformed-record.
    display 'ERROR MALFORMED-RECORD'
    move 1 to return-code
    goback.
