import numpy as np
from random import randint
import itertools
from argparse import ArgumentParser
from collections import Counter

class diff_cryptanalysis():
    def __init__(self, s_box=0):
        if s_box != 0:
            self.s_box = s_box
        else:
            self.s_box = [14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6,
             6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
             4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11,
             9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13]

        self.s_box_binary = np.zeros((64, 16), dtype=int) # tablica rozkladow
        self.input_pair_array = [[[0 for x in range(0)] for y in range(16)] for z in range(64)] 


    def generate_distribution_of_differences(self):
        #print(f"inp = {np.array(input_pair_array).shape}")

        for i in range(64):
            for j in range(i, 64):
                xor_in = i^j
                xor_out = self.s_box[i] ^ self.s_box[j]
                self.s_box_binary[xor_in, xor_out] += 1
                self.input_pair_array[xor_in][xor_out].append((i,j))

        for i in range(63, -1, -1):
            for j in range(63, i, -1):
                xor_in = i^j
                xor_out = self.s_box[i] ^ self.s_box[j]
                self.s_box_binary[xor_in, xor_out] += 1
                self.input_pair_array[xor_in][xor_out].append((j,i))
                
        self.check_sbox_row_sums()
            
        #np.savetxt('generated_xor_block.txt', s_box_binary, fmt='%d')
        #np.savetxt('generated_xor_block.csv', s_box_binary, delimiter=',', fmt='%s')
        
    def check_sbox_row_sums(self):
        for i in range(64):
            sum_of_row = np.sum(self.s_box_binary[i,:], axis=0)
            if sum_of_row !=64:
                print(f"Sum of row {i} = {sum_of_row}")

                
    def find_row_with_highest_val(self):
        #Row with 64 bits not taken into account
        max_row_id = -1
        max_row_val = -1
        for i in range(len(self.s_box_binary[:])):
            curr_max_row_val = max(self.s_box_binary[i])
            #print(f"curr max val = {curr_max_row_val} vs max_row_val = {max_row_val}")
            if curr_max_row_val > max_row_val and curr_max_row_val != 64:
                max_row_val = curr_max_row_val
                max_row_id = i

        return max_row_id



    def find_probable_keys(self, A_IN, B_IN, A_sbox_out, B_sbox_out, quiet=False):
        XOR_in = A_IN ^ B_IN
        XOR_out = A_sbox_out ^ B_sbox_out
       
        probable_keys = []
        for pairs in self.input_pair_array[XOR_in][XOR_out]:
            probable_keys.append(hex(pairs[0]^A_IN))

        if not quiet:
            print(f"A = {hex(A_IN)}, B = {hex(B_IN)}")
            print(f"A_sbox_out = {hex(A_sbox_out)}, B_sbox_out = {hex(B_sbox_out)}")
            print(f"xor_in = {hex(XOR_in)}, xor_out = {hex(XOR_out)}")
            print(f"Input SBOX pairs giving output XOR = {hex(XOR_out)} [input xor = {hex(XOR_in)}]:")
            print(f"{self.input_pair_array[XOR_in][XOR_out]}")

            print("----------")
            print(f"Probable keys = {probable_keys}")
            
        return probable_keys
    
def cipher(A, B, key, s_box=0):
    if s_box != 0:
        s_box = s_box
    else:
        s_box = [14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6,
         6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
         4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11,
         9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13]

    A_key = A^key
    B_key = B^key

    A_sbox_out = s_box[A_key]
    B_sbox_out = s_box[B_key]

    return (A_sbox_out, B_sbox_out)


def main():
    parser = ArgumentParser()
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="don't print status messages to stdout")

    args = parser.parse_args()
    
    
    diff_crypt = diff_cryptanalysis()
    diff_crypt.generate_distribution_of_differences()
    #max_row_id = diff_crypt.find_row_with_highest_val()
    #print(s_box_binary[max_row_id])

    A_IN = input("Type max 6bit numbers:\n").strip().split(" ")
    A_IN = list(map(int, A_IN))
    A_IN_arr = []
    for x in A_IN:
        if x>2**6-1 or x<0:
            print(f"{x} is out of bounds - discarding")
        else:
            A_IN_arr.append(x)
   
    input_combs = set(list(itertools.combinations(A_IN_arr, 2))) #Create every combination of input data
    if not args.quiet:
        print(f"number of combinations = {len(input_combs)}")
        print(f"all input cominations = {input_combs}")
    all_probable_keys = []
    
    SECRET_KEY = randint(0, 2**6-1) #Key we are trying to guess
    print(f"SECRET_KEY = {hex(SECRET_KEY)}\n")
    
    for num, (A_IN, B_IN) in enumerate(input_combs):
        if not args.quiet:
            print(f"Checking number {num+1} pair:")
        (A_sbox_out, B_sbox_out) = cipher(A_IN, B_IN, key=SECRET_KEY)
        probable_keys = diff_crypt.find_probable_keys(A_IN, B_IN, A_sbox_out, B_sbox_out, args.quiet)
        all_probable_keys += probable_keys
        if not args.quiet:
            print('----------------------end---------------------\n')

    only_possible_keys = []
    cnt = Counter(all_probable_keys)
    for item_key, item_val in cnt.most_common():
        if item_val != len(input_combs):
            break
        only_possible_keys.append(item_key)

    print('--------------------------------------------------------\n')
    print(f"Most common keys are = {only_possible_keys}")
    
if __name__ == "__main__":
    main()


