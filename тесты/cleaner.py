#!/usr/bin/env python3
import os

extensions = {'.аст', '.csv', '.токены', '.проход1', '.elf'}

for file in os.listdir('.'):
    if os.path.isfile(file) and os.path.splitext(file)[1] in extensions:
        os.remove(file)
        #print(f'Удален: {file}')