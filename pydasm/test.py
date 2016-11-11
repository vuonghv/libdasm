# To run test:
# python -m unittest test
#
import unittest
import pydasm


class TestPydasm(unittest.TestCase):

    def test_get_instruction_string(self):
        buffer = b'\x90\x31\xc9\x31\xca\x31\xcb'
        offset = 0
        dasm = ''
        expected = (
            'nop '
            'xor ecx,ecx'
            'xor edx,ecx'
            'xor ebx,ecx'
        )
        
        while offset < len(buffer):
            instruction = pydasm.get_instruction(buffer[offset:], pydasm.MODE_32)
            dasm += pydasm.get_instruction_string(instruction, pydasm.FORMAT_INTEL, 0)
            if not instruction:
                break
            offset += instruction.length
        
        self.assertEqual(dasm, expected)

