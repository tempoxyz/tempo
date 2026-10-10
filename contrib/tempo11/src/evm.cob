identification division.
program-id. tempo11-evm.
environment division.
configuration section.
repository. function all intrinsic.
data division.
working-storage section.
01 hex-digits pic x(16) value '0123456789abcdef'.
01 source-code pic x(65538).
01 code-bytes pic x(32768).
01 code-length usage binary-long.
01 argument-count usage binary-long.
01 pc usage binary-long value 1.
01 opcode usage binary-long.
01 sp usage binary-long value 0.
01 evm-stack.
   02 stack-word pic x(32) occurs 1024 times.
01 a-word pic x(32).
01 b-word pic x(32).
01 result-word pic x(32).
01 output-word pic x(64).
01 output-number pic Z(9)9.
01 i usage binary-long.
01 j usage binary-long.
01 k usage binary-long.
01 n usage binary-long.
01 high-nibble usage binary-long.
01 low-nibble usage binary-long.
01 a-byte usage binary-long.
01 b-byte usage binary-long.
01 result-byte usage binary-long.
01 carry-byte usage binary-long.
01 bit-weight usage binary-long.
01 a-bit usage binary-long.
01 b-bit usage binary-long.
01 operation-value usage binary-long.
01 products.
   02 product-limb usage binary-long unsigned occurs 64 times.
procedure division.
    accept argument-count from argument-number
    if argument-count not = 1
        display 'ERROR EXPECT-HEX-BYTECODE'
        move 1 to return-code
        goback
    end-if
    accept source-code from argument-value
    move function lower-case(source-code) to source-code
    compute code-length = function length(trim(source-code trailing))
    if code-length > 65536 or function mod(code-length, 2) not = 0
        perform invalid-hex
    end-if
    perform varying i from 1 by 2 until i > code-length
        move 0 to high-nibble low-nibble
        inspect hex-digits tallying high-nibble for characters
            before initial source-code(i:1)
        inspect hex-digits tallying low-nibble for characters
            before initial source-code(i + 1:1)
        if high-nibble = 16 or low-nibble = 16
            perform invalid-hex
        end-if
        compute n = function integer((i + 1) / 2)
        move function char(high-nibble * 16 + low-nibble + 1)
            to code-bytes(n:1)
    end-perform
    divide 2 into code-length
    perform until pc > code-length
        compute opcode = function ord(code-bytes(pc:1)) - 1
        add 1 to pc
        evaluate true
            when opcode = 0
                exit perform
            when opcode >= 95 and opcode <= 127
                perform check-overflow
                add 1 to sp
                move low-values to stack-word(sp)
                compute n = opcode - 95
                *> Missing PUSH immediate bytes are zero-padded by EVM.
                perform varying i from 1 by 1 until i > n
                    if pc <= code-length
                        move code-bytes(pc:1)
                            to stack-word(sp)(32 - n + i:1)
                    end-if
                    add 1 to pc
                end-perform
            when opcode >= 128 and opcode <= 143
                compute n = opcode - 127
                if sp < n perform underflow-error end-if
                perform check-overflow
                move stack-word(sp - n + 1) to a-word
                add 1 to sp
                move a-word to stack-word(sp)
            when opcode >= 144 and opcode <= 159
                compute n = opcode - 143
                if sp <= n perform underflow-error end-if
                move stack-word(sp) to a-word
                move stack-word(sp - n) to stack-word(sp)
                move a-word to stack-word(sp - n)
            when opcode = 80
                if sp < 1 perform underflow-error end-if
                subtract 1 from sp
            when opcode = 88
                perform check-overflow
                add 1 to sp
                move low-values to stack-word(sp)
                compute operation-value = pc - 2
                perform varying i from 32 by -1 until i < 1
                    move function char(
                        function mod(operation-value, 256) + 1)
                        to stack-word(sp)(i:1)
                    compute operation-value =
                        function integer(operation-value / 256)
                end-perform
            when opcode = 21 or opcode = 25
                if sp < 1 perform underflow-error end-if
                move stack-word(sp) to a-word
                move low-values to result-word
                if opcode = 21
                    if a-word = low-values
                        move x'01' to result-word(32:1)
                    end-if
                else
                    perform varying i from 1 by 1 until i > 32
                        move function char(
                            257 - function ord(a-word(i:1)))
                            to result-word(i:1)
                    end-perform
                end-if
                move result-word to stack-word(sp)
            when opcode = 1 or 2 or 3 or 16 or 17 or 20
                or 22 or 23 or 24 or 26
                if sp < 2 perform underflow-error end-if
                move stack-word(sp) to a-word
                subtract 1 from sp
                move stack-word(sp) to b-word
                move low-values to result-word
                perform binary-operation
                move result-word to stack-word(sp)
            when other
                display 'ERROR UNSUPPORTED-OPCODE'
                move 1 to return-code
                goback
        end-evaluate
    end-perform
    move sp to output-number
    display 'STACK ' trim(output-number)
    perform varying k from 1 by 1 until k > sp
        perform varying i from 1 by 1 until i > 32
            compute a-byte = function ord(stack-word(k)(i:1)) - 1
            compute n = i * 2 - 1
            move hex-digits(function integer(a-byte / 16) + 1:1)
                to output-word(n:1)
            move hex-digits(function mod(a-byte, 16) + 1:1)
                to output-word(n + 1:1)
        end-perform
        display output-word
    end-perform
    move 0 to return-code
    goback.
binary-operation.
    evaluate opcode
        when 1 when 3
            move 0 to carry-byte
            perform varying i from 32 by -1 until i < 1
                compute a-byte = function ord(a-word(i:1)) - 1
                compute b-byte = function ord(b-word(i:1)) - 1
                if opcode = 1
                    compute result-byte = a-byte + b-byte + carry-byte
                else
                    compute result-byte = a-byte - b-byte + carry-byte
                end-if
                compute carry-byte = function integer(result-byte / 256)
                move function char(function mod(result-byte, 256) + 1)
                    to result-word(i:1)
            end-perform
        when 2
            initialize products
            perform varying i from 1 by 1 until i > 32
                perform varying j from 1 by 1 until j > 32
                    compute product-limb(i + j) = product-limb(i + j)
                        + (function ord(a-word(i:1)) - 1)
                        * (function ord(b-word(j:1)) - 1)
                end-perform
            end-perform
            perform varying i from 64 by -1 until i < 33
                compute product-limb(i - 1) = product-limb(i - 1)
                    + function integer(product-limb(i) / 256)
                move function char(function mod(product-limb(i), 256) + 1)
                    to result-word(i - 32:1)
            end-perform
        when 16
            if a-word < b-word move x'01' to result-word(32:1) end-if
        when 17
            if a-word > b-word move x'01' to result-word(32:1) end-if
        when 20
            if a-word = b-word move x'01' to result-word(32:1) end-if
        when 26
            if a-word(1:31) = low-values
                compute n = function ord(a-word(32:1)) - 1
                if n < 32
                    move b-word(n + 1:1) to result-word(32:1)
                end-if
            end-if
        when other
            perform varying i from 1 by 1 until i > 32
                compute a-byte = function ord(a-word(i:1)) - 1
                compute b-byte = function ord(b-word(i:1)) - 1
                move 0 to result-byte
                move 1 to bit-weight
                perform 8 times
                    compute a-bit = function mod(a-byte, 2)
                    compute b-bit = function mod(b-byte, 2)
                    evaluate opcode
                        when 22
                            if a-bit = 1 and b-bit = 1
                                add bit-weight to result-byte
                            end-if
                        when 23
                            if a-bit = 1 or b-bit = 1
                                add bit-weight to result-byte
                            end-if
                        when 24
                            if a-bit not = b-bit
                                add bit-weight to result-byte
                            end-if
                    end-evaluate
                    multiply 2 by bit-weight
                    compute a-byte = function integer(a-byte / 2)
                    compute b-byte = function integer(b-byte / 2)
                end-perform
                move function char(result-byte + 1) to result-word(i:1)
            end-perform
    end-evaluate.
check-overflow.
    if sp = 1024
        display 'ERROR STACK-OVERFLOW'
        move 1 to return-code
        goback
    end-if.
underflow-error.
    display 'ERROR STACK-UNDERFLOW'
    move 1 to return-code
    goback.
invalid-hex.
    display 'ERROR INVALID-HEX'
    move 1 to return-code
    goback.
