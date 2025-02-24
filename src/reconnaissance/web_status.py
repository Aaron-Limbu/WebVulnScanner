import requests 
import os 
import logging 
import argparse

class Logger: 
    @staticmethod 
    def setuplogger(): 

class Web_status_handler: 
    def __init__(domain):
        self.domain = domain

class CLI: 
    @staticmethod 
    def arguement_parser():
        parser = argparse.ArgumentParser(description="website alive or dead checker")
        parser.add_srgument("-d","--domain",type=str,help="eg: https://www.domainname.com")
        return parser.parse_args()

class Application: 

if __name__ == "__main__":
