# -*- coding: utf-8 -*-

import argparse
import importlib
import importlib.resources as pkg_resources
import importlib.util
import ipaddress
import os
import pathlib
import queue
import re
import signal
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import List, Optional, Set, Dict, Any, Union
from queue import Queue

if __package__:
    from .logger import Logger
    from .navigator import Navigator
    from .detector import Detector
    from .cache import Cache
    from .output import OutputFormatter, StreamingOutputWriter
    from .display import create_display, ANSI
    from .config import default_config
else:
    from logger import Logger
    from navigator import Navigator
    from detector import Detector
    from cache import Cache
    from output import OutputFormatter, StreamingOutputWriter
    from display import create_display, ANSI
    from config import default_config

# Initialize global color references from ANSI (will be updated in main() if --no-colors)
reset = ANSI.RESET
light_grey = ANSI.WHITE
dark_grey = ANSI.BRIGHT_BLACK
red = ANSI.RED
green = ANSI.GREEN
bold = ANSI.BOLD
yellow = ANSI.BRIGHT_YELLOW
blue = ANSI.BRIGHT_CYAN
bright_red = ANSI.BRIGHT_RED


def disable_all_colors():
    """Disable all colors globally."""
    global reset, light_grey, dark_grey, red, green, bold, yellow, blue, bright_red
    ANSI.disable_colors()
    reset = ''
    light_grey = ''
    dark_grey = ''
    red = ''
    green = ''
    bold = ''
    yellow = ''
    blue = ''
    bright_red = ''

version = '1.6.0'


def banner(colors_enabled=True):
    # Format function: handles all color codes in the banner
    def ff(color_code):
        """Format function - converts color codes or strips them based on colors_enabled"""
        if colors_enabled:
            # Convert [38;5;XXXm to ANSI escape codes
            return f'\u001b[38;5;{color_code}m'
        else:
            # Strip color codes, keep characters (so banner is still visible)
           return ''

    head = f'''       {ff(103)} {ff(103)}                                                                      {ff(102)} {ff(103)}                 
       {ff(103)}΄{ff(98)}Υ{ff(98)}κ{ff(97)}κ{ff(97)};{ff(103)}                                                  {ff(102)} {ff(102)}            {ff(103)} {ff(97)}ν{ff(134)}Η{ff(134)}Η{ff(97)};                
        {ff(98)}Ύ{ff(98)}Η{ff(97)}κ{ff(97)}΅{ff(134)}Κ{ff(134)}Ν{ff(134)}Κ{ff(97)};{ff(102)}                                            {ff(102)} {ff(97)}Μ{ff(102)}         {ff(102)} {ff(97)};{ff(134)}Κ{ff(134)}Ν{ff(133)}Μ{ff(97)}γ{ff(97)}Ύ{ff(134)}Κ{ff(97)}΅                
        {ff(103)}΄{ff(134)}Η{ff(134)}Ή{ff(102)}  {ff(102)} {ff(103)}΄{ff(133)}Ύ{ff(134)}Ν{ff(134)}Ν{ff(133)}η{ff(103)}                                       {ff(102)} {ff(133)}ύ{ff(97)}΅       {ff(103)} {ff(133)}υ{ff(134)}Ν{ff(134)}Ν{ff(133)}Μ{ff(103)}΄ {ff(102)}  {ff(134)}ή{ff(134)}Η{ff(97)}                 
         {ff(97)}Ύ{ff(134)}Η{ff(97)}ι   {ff(102)}΄{ff(102)} {ff(103)}΄{ff(133)}΅{ff(134)}Κ{ff(134)}Ν{ff(134)}Ν{ff(103)};   {ff(102)} {ff(102)}                             {ff(102)} {ff(133)}υ{ff(97)}Μ{ff(102)}      {ff(103)} {ff(133)}υ{ff(134)}Ν{ff(134)}Ν{ff(133)}Μ{ff(103)}΅ {ff(102)}    {ff(102)} {ff(134)}Ν{ff(134)}Ν                 
         {ff(102)} {ff(134)}Ν{ff(134)}Ν      {ff(102)}  {ff(102)} {ff(139)}΅{ff(134)}Κ{ff(134)}Ν{ff(134)}Ν{ff(139)}; {ff(103)}΄{ff(103)}                           {ff(97)}κ{ff(97)}Μ{ff(102)}     {ff(102)} {ff(133)}υ{ff(134)}Ν{ff(134)}Ν{ff(133)}Μ{ff(103)}΄ {ff(102)} {ff(102)} {ff(102)}     {ff(103)}΄{ff(134)}Ν{ff(103)} {ff(103)}                 
         {ff(103)} {ff(97)}΄{ff(134)}Ν{ff(133)}κ      {ff(102)}     {ff(103)}΄{ff(134)}Κ{ff(134)}Ν{ff(134)}Ν{ff(134)}Ν{ff(133)};{ff(133)};     {ff(103)}                  {ff(97)}΄     {ff(97)};{ff(134)}Ν{ff(134)}Ν{ff(134)}Μ{ff(103)}΄  {ff(102)} {ff(103)}΄       {ff(134)}Ν{ff(134)}Ν{ff(103)} {ff(102)}                 
          {ff(97)}κ{ff(133)}Ύ{ff(134)}Ν{ff(102)}       {ff(97)} {ff(97)} {ff(103)}     {ff(103)}΄{ff(134)}Ν{ff(134)}Κ{ff(134)}β{ff(134)}Ν{ff(133)}η    {ff(97)}΅{ff(103)}                   {ff(103)} {ff(133)}ή{ff(134)}Ή{ff(134)}Κ{ff(97)}΅{ff(102)}   {ff(102)} {ff(102)}         {ff(102)} {ff(134)}Ν{ff(133)}υ{ff(97)}΅                 
   {ff(102)}       {ff(102)}΄{ff(134)}Κ{ff(134)}Ν{ff(134)}Ν        {ff(97)}΅{ff(98)}Η{ff(97)}ν{ff(103)}     {ff(139)}΅{ff(134)}Ώ{ff(134)}ή{ff(134)}Κ{ff(133)}μ{ff(102)}             {ff(102)} {ff(103)}΄     {ff(103)} {ff(134)}Ν{ff(134)}Ν{ff(133)}Μ{ff(103)}                {ff(133)}κ{ff(134)}Ν{ff(134)}Ν                  
    {ff(103)}΄{ff(103)}      {ff(102)} {ff(134)}Κ{ff(134)}Ν{ff(97)};        {ff(103)}΄{ff(98)}Υ{ff(97)}΄{ff(97)}΅{ff(97)};    {ff(103)}΄{ff(139)}Μ{ff(103)} {ff(139)}΅{ff(139)}ν           {ff(102)}   {ff(102)}  {ff(102)} {ff(134)}Π{ff(134)}Κ{ff(103)}΄         {ff(102)} {ff(102)}       {ff(102)} {ff(134)}Ν{ff(134)}Ν{ff(102)}                   
          {ff(103)}  {ff(102)}΄{ff(134)}Κ{ff(134)}Ν{ff(102)}          {ff(103)}΄  {ff(102)}΄{ff(102)}        {ff(102)}΄            {ff(102)}  {ff(103)} {ff(103)}΄{ff(103)}          {ff(102)} {ff(103)}΄{ff(102)}        {ff(133)}γ{ff(134)}Ν{ff(97)}΄  {ff(102)}΄                
           {ff(97)}΅{ff(133)}η{ff(103)} {ff(134)}Κ{ff(134)}Π{ff(102)}                                             {ff(102)} {ff(102)}           {ff(102)} {ff(134)}Ν{ff(133)}Μ       {ff(102)}        {ff(103)} {ff(102)}    
            {ff(102)} {ff(134)}Κ{ff(134)}Ν{ff(134)}Κ{ff(134)}Ν      {ff(102)}΄{ff(138)} {ff(138)} {ff(138)}          {ff(102)} {ff(102)}                    {ff(102)} {ff(102)}      {ff(102)} {ff(102)} {ff(102)}       {ff(134)}Ν{ff(134)}Κ            {ff(103)} {ff(97)} {ff(97)}ν{ff(97)}΅{ff(102)}     
      {ff(97)}ν{ff(97)};      {ff(103)}΄{ff(134)}Κ{ff(133)}ω{ff(139)}΅        {ff(102)}΄{ff(132)}΄{ff(132)}΅{ff(132)}ν{ff(138)}        {ff(103)} {ff(102)}            {ff(103)} {ff(102)}        {ff(138)} {ff(132)} {ff(132)}΄{ff(138)}΄        {ff(103)} {ff(134)}Ν   {ff(102)} {ff(103)} {ff(102)}      {ff(103)} {ff(97)}΅{ff(97)}΅{ff(97)}ν{ff(97)}΅      
                {ff(103)}΄{ff(134)}Ν{ff(103)}          {ff(138)}  {ff(102)}΄{ff(132)}΄{ff(138)} {ff(102)}      {ff(102)}΄{ff(103)}        {ff(102)} {ff(103)} {ff(103)}       {ff(102)} {ff(138)}΄{ff(138)}΄            {ff(134)}Ν  {ff(102)} {ff(103)} {ff(103)}                   
{ff(102)}    {ff(102)} {ff(103)}             {ff(103)}΄{ff(103)}      {ff(102)}   {ff(166)}Κ{ff(166)}Ν{ff(172)}β{ff(172)}Ν{ff(137)}υ     {ff(102)}΄{ff(138)}  {ff(103)}      {ff(103)}΄{ff(103)}         {ff(137)} {ff(137)}υ{ff(173)}η{ff(172)}Ν{ff(166)}Κ         {ff(102)}΄                        
      {ff(133)}΅{ff(133)}Κ{ff(103)}        {ff(102)} {ff(102)}         {ff(103)}  {ff(102)} {ff(172)}Ν{ff(172)}Ν{ff(172)}Κ{ff(178)}Ή{ff(143)}ω  {ff(138)};   {ff(102)}΄         {ff(102)} {ff(138)}     {ff(143)};{ff(179)}β{ff(178)}Ν{ff(172)}Ν{ff(172)}Ν{ff(138)}  {ff(102)}          {ff(102)}        {ff(103)}               
       {ff(102)}΄{ff(134)}Κ{ff(134)}β{ff(133)}Κ{ff(139)};{ff(102)}  {ff(102)} {ff(103)}   {ff(102)}  {ff(102)}   {ff(102)}    {ff(102)}   {ff(178)}Ά{ff(178)}Ν{ff(178)}Ν{ff(178)}Ώ{ff(102)}  {ff(178)}Ώ{ff(178)}Ν{ff(179)}Ν{ff(138)}         {ff(102)} {ff(138)}΄ {ff(137)} {ff(178)}β{ff(178)}Κ{ff(102)}  {ff(179)}β{ff(178)}Ν{ff(178)}Ν{ff(178)}Ώ{ff(137)}  {ff(103)}     {ff(103)} {ff(103)} {ff(102)} {ff(102)} {ff(103)}΄    {ff(102)} {ff(103)} {ff(133)}Λ{ff(139)}΅{ff(102)}                
            {ff(102)} {ff(103)} {ff(139)};{ff(139)}κ{ff(139)}΅{ff(103)}    {ff(103)}΄{ff(103)}΄{ff(103)} {ff(103)} {ff(103)}      {ff(102)} {ff(143)}΅{ff(179)}Ά{ff(185)}Ώ{ff(179)}φ{ff(184)}Ν{ff(178)}Ν{ff(178)}Ά{ff(143)}΅{ff(143)}΅        {ff(143)} {ff(179)}Μ{ff(178)}Β{ff(178)}β{ff(184)}β{ff(179)}ψ{ff(185)}β{ff(184)}Ν{ff(179)}Ν{ff(143)}΅  {ff(102)}   {ff(102)} {ff(103)} {ff(103)} {ff(102)}   {ff(102)} {ff(103)} {ff(139)}ν{ff(133)}Η{ff(134)}Κ{ff(134)}Η{ff(133)}΅{ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(103)}΄{ff(103)}΄{ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(102)}    
      {ff(102)}΄{ff(102)}΅  {ff(103)} {ff(139)}υ{ff(134)}Μ{ff(103)}΅{ff(103)};{ff(145)}ε{ff(188)}β{ff(188)}Έ{ff(188)}β{ff(145)}ω {ff(102)}     {ff(102)}              {ff(102)}             {ff(144)} {ff(144)}΄{ff(144)}      {ff(102)} {ff(102)}΄{ff(102)}     {ff(103)} {ff(97)}΄{ff(134)}Κ{ff(133)}Μ{ff(133)}Μ{ff(133)}΅{ff(97)}΅{ff(103)}΅{ff(103)}΄{ff(103)}΄{ff(103)} {ff(103)} {ff(103)} {ff(103)};{ff(103)};{ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(103)};    {ff(103)} {ff(103)}΄  
   {ff(102)}   {ff(102)} {ff(139)}υ{ff(134)}Κ{ff(133)}΅{ff(103)} {ff(139)}μ{ff(182)}φ{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(102)} {ff(103)}΄{ff(102)}    {ff(102)} {ff(103)} {ff(102)}  {ff(102)}         {ff(145)}ς{ff(182)}Έ{ff(103)}΄            {ff(103)};{ff(145)};{ff(102)} {ff(102)} {ff(103)} {ff(102)}   {ff(102)} {ff(103)} {ff(103)} {ff(102)}   {ff(102)} {ff(102)} {ff(103)} {ff(139)};{ff(145)}μ{ff(145)}φ{ff(182)}φ{ff(188)}β{ff(188)}Έ{ff(188)}φ{ff(188)}φ{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Ώ    {ff(102)}    
    {ff(97)};{ff(134)}Ν{ff(133)}΅{ff(103)} {ff(103)};{ff(145)}φ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}β{ff(188)}Ψ{ff(102)} {ff(140)}Ύ{ff(102)} {ff(102)} {ff(102)} {ff(139)}   {ff(102)} {ff(102)} {ff(145)}ω{ff(188)}β{ff(188)}Έ{ff(102)} {ff(102)} {ff(182)}έ{ff(188)}Έ{ff(182)}Ό{ff(188)}β {ff(102)}        {ff(102)} {ff(102)} {ff(145)}μ{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(103)} {ff(139)}λ{ff(102)} {ff(102)} {ff(103)};{ff(145)}μ{ff(145)}φ{ff(145)}φ{ff(188)}β{ff(139)} {ff(146)}Έ{ff(188)}Ώ{ff(188)}Ώ{ff(188)}φ{ff(188)}β{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Φ{ff(188)}Φ{ff(188)}Ρ{ff(145)}Έ{ff(145)}Ό        
 {ff(103)} {ff(133)}Κ{ff(134)}Ή{ff(103)}΄{ff(103)} {ff(139)};{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(145)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(102)} {ff(102)} {ff(145)};{ff(145)}ς{ff(188)}Έ{ff(145)}Μ {ff(102)} {ff(102)} {ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(139)};{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(145)}μ{ff(145)}φ{ff(145)}φ{ff(188)}β{ff(188)}β{ff(145)}Έ{ff(102)} {ff(102)} {ff(102)} {ff(145)}υ{ff(188)}Ώ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(103)} {ff(103)} {ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Ψ{ff(103)} {ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(103)} {ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)}      {ff(102)}    
{ff(133)}ί{ff(134)}Κ{ff(103)} {ff(103)} {ff(145)}χ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(145)}΅{ff(103)} {ff(103)} {ff(103)} {ff(145)}Χ{ff(145)}Ό{ff(103)} {ff(145)}΅{ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(188)}β{ff(188)}Ψ{ff(188)}β{ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(188)}Ν{ff(188)}Έ{ff(188)}Έ{ff(145)}Μ{ff(103)} {ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(103)} {ff(103)}΄{ff(188)}φ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(145)}΅{ff(103)} {ff(188)}Ϊ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(103)} {ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Β{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(139)} {ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(188)}β{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(145)}Ή {ff(102)}      {ff(102)} {ff(102)} {ff(103)} {ff(103)}΄{ff(103)}      
{ff(139)};{ff(134)}ψ{ff(102)} {ff(139)}΄{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}φ{ff(182)}φ{ff(145)}ω{ff(145)}ω{ff(103)} {ff(102)} {ff(102)} {ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(145)}φ{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(188)}β{ff(188)}Έ{ff(188)}β{ff(103)} {ff(103)} {ff(188)}φ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(103)};{ff(146)}φ{ff(188)}Έ{ff(188)}Έ{ff(146)}Ό{ff(103)} {ff(103)} {ff(103)} {ff(139)}ν{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(145)}Ό{ff(102)} {ff(102)} {ff(102)} {ff(188)}έ{ff(188)}β{ff(145)}Μ{ff(145)}Μ{ff(103)} {ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(146)}Έ{ff(103)} {ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Ψ{ff(103)} {ff(103)} {ff(102)} {ff(102)} {ff(103)} {ff(188)}β{ff(188)}Έ{ff(188)}β{ff(188)}β   {ff(97)}΄   {ff(102)}           
 {ff(139)}΅{ff(102)}  {ff(139)}΄{ff(188)}Φ{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(146)}φ{ff(145)}μ{ff(103)} {ff(103)} {ff(103)} {ff(188)}β{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(145)}Μ{ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(145)}Τ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(146)}μ{ff(145)}μ{ff(146)}φ{ff(146)}φ{ff(103)} {ff(146)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(145)}Μ{ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(145)}χ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(103)} {ff(146)}β{ff(188)}Ώ{ff(188)}β{ff(188)}Έ{ff(145)}ψ{ff(145)}μ{ff(139)}ι{ff(103)} {ff(145)}Υ{ff(188)}β{ff(188)}Έ{ff(188)}Ώ{ff(182)}Έ{ff(102)}  {ff(103)} {ff(103)}  {ff(103)}             
       {ff(102)} {ff(103)} {ff(139)}΄{ff(145)}Ϊ{ff(182)}Ώ{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(182)}ώ{ff(188)}Β{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(145)}Ϊ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(103)} {ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Ά{ff(182)}Έ{ff(146)}Ϊ{ff(145)}Ϊ{ff(145)}Ϊ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(102)} {ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(103)};{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Ώ{ff(145)}Ϊ{ff(139)}΄{ff(103)} {ff(188)}β{ff(188)}β{ff(188)}β{ff(145)}Ί{ff(103)} {ff(102)} {ff(102)} {ff(134)}Κ               
           {ff(102)} {ff(103)} {ff(103)}΅{ff(103)} {ff(103)} {ff(145)}Ϊ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(145)}Έ{ff(188)}φ{ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(182)}Έ{ff(103)} {ff(145)}γ{ff(188)}Έ{ff(188)}Έ{ff(146)}Ή{ff(103)} {ff(103)} {ff(103)} {ff(145)}ε{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}φ{ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(145)}μ{ff(146)}φ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(182)}Έ{ff(145)}Ϊ{ff(145)}΅{ff(103)} {ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(103)} {ff(103)} {ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(145)}Γ{ff(102)} {ff(102)} {ff(134)}Λ{ff(103)}     {ff(103)} {ff(102)}          
      {ff(103)} {ff(139)}Μ{ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(103)} {ff(145)}μ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(188)}φ{ff(188)}β{ff(188)}Έ{ff(188)}φ{ff(188)}Έ{ff(188)}Έ{ff(103)} {ff(139)}μ{ff(182)}φ{ff(188)}Έ{ff(188)}β{ff(188)}β{ff(188)}β{ff(146)}Έ{ff(103)} {ff(182)}β{ff(188)}β{ff(188)}Έ{ff(139)};{ff(145)}μ{ff(182)}φ{ff(188)}β{ff(188)}β{ff(188)}β{ff(182)}Έ{ff(146)}Ό{ff(103)} {ff(188)}Ϊ{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(103)} {ff(103)} {ff(145)}μ{ff(182)}φ{ff(188)}Έ{ff(188)}β{ff(188)}Έ{ff(182)}Ώ{ff(188)}β{ff(188)}β{ff(146)}Ώ{ff(102)} {ff(102)} {ff(103)} {ff(103)} {ff(102)} {ff(145)}π{ff(188)}β{ff(188)}β{ff(188)}β{ff(103)} {ff(102)} {ff(103)} {ff(182)}Ώ{ff(188)}β{ff(139)}  {ff(102)} {ff(103)} {ff(134)}Κ{ff(102)}   {ff(102)}             
  {ff(103)}  {ff(103)} {ff(139)}Μ{ff(102)}  {ff(102)} {ff(102)} {ff(103)} {ff(145)}μ{ff(182)}β{ff(188)}φ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Έ{ff(182)}Έ{ff(103)} {ff(103)} {ff(188)}Β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Ώ{ff(182)}β{ff(182)}Έ{ff(145)}΅{ff(188)}Έ{ff(139)}΅{ff(146)}Ψ{ff(103)} {ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}Ώ{ff(188)}Β{ff(182)}Ά{ff(145)}΅{ff(103)} {ff(103)} {ff(103)} {ff(102)} {ff(103)} {ff(182)}Φ{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(188)}β{ff(182)}Έ{ff(145)}΅{ff(103)} {ff(182)}β{ff(182)}Ώ{ff(182)}Έ{ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(182)}β{ff(182)}Ώ{ff(182)}Β{ff(146)}Έ{ff(102)} {ff(139)}΄{ff(146)}φ{ff(182)}Ώ{ff(102)} {ff(102)}  {ff(134)}Ν{ff(134)}ζ{ff(103)} {ff(102)}               
  {ff(103)} {ff(133)}Μ{ff(103)}΄  {ff(102)} {ff(103)} {ff(140)}έ{ff(182)}Β{ff(182)}Ώ{ff(182)}Ώ{ff(182)}Ώ{ff(182)}Έ{ff(188)}β{ff(182)}Έ{ff(145)}΅{ff(103)} {ff(102)}΄{ff(102)} {ff(102)} {ff(102)} {ff(139)}΄{ff(145)}Ϊ{ff(146)}Έ{ff(139)}΅{ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(103)} {ff(182)}φ{ff(182)}Ά{ff(182)}Ρ{ff(139)}Ό{ff(139)}΄{ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(139)}΅{ff(145)}Ό{ff(145)}Ό{ff(139)}΅{ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(139)}΄{ff(102)} {ff(102)}     {ff(102)}΄ {ff(102)} {ff(140)}ψ{ff(103)}΄{ff(140)}Ώ{ff(102)} {ff(102)} {ff(140)}β{ff(139)}Ή {ff(102)} {ff(97)}ι{ff(97)}΅{ff(134)}ή{ff(134)}Κ{ff(134)}Ν{ff(103)}              
 {ff(103)}    {ff(103)} {ff(139)}η{ff(140)}β{ff(176)}β{ff(176)}β{ff(176)}β{ff(176)}Ώ{ff(182)}φ{ff(146)}Έ{ff(139)}΅{ff(103)} {ff(102)} {ff(102)}   {ff(102)}  {ff(102)} {ff(103)}΄{ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(103)} {ff(103)} {ff(103)};{ff(139)}υ{ff(139)}ρ{ff(140)}θ{ff(140)}Κ{ff(134)}β{ff(134)}Θ{ff(134)}β{ff(134)}Ώ{ff(134)}Ν{ff(134)}Ν{ff(134)}β{ff(134)}Ν{ff(134)}Ν{ff(134)}Ή{ff(134)}Ν{ff(134)}Ν{ff(134)}Ν{ff(134)}Ν{ff(134)}Ν{ff(134)}Ν{ff(134)}Ν{ff(134)}Ώ{ff(134)}Ν{ff(140)}Κ{ff(139)}Μ{ff(139)}Μ{ff(139)}Μ{ff(139)}υ{ff(139)}υ{ff(103)};{ff(103)} {ff(103)}     {ff(139)}ΐ{ff(102)}  {ff(134)}Ή{ff(102)} {ff(103)} {ff(102)} {ff(97)}Μ       {ff(102)}           
    {ff(103)} {ff(139)}υ{ff(140)}Ώ{ff(140)}Κ{ff(140)}Ώ{ff(140)}Ά{ff(139)}Μ{ff(103)} {ff(102)} {ff(103)} {ff(103)} {ff(103)} {ff(102)}΅{ff(102)}  {ff(102)} {ff(102)}  {ff(102)} {ff(103)} {ff(103)} {ff(139)}η{ff(133)}μ{ff(134)}Κ{ff(134)}Κ{ff(134)}Ν{ff(134)}Ν{ff(134)}Ν{ff(134)}Ν{ff(134)}β{ff(134)}Ν{ff(134)}Ν{ff(134)}Μ{ff(133)}Μ{ff(133)}΅{ff(133)}΅{ff(103)}΅{ff(139)}΅{ff(139)};{ff(139)};{ff(139)};{ff(139)};{ff(103)}υ{ff(103)} {ff(103)} {ff(103)} {ff(103)} {ff(102)} {ff(102)}      {ff(102)}               {ff(134)}Κ {ff(102)} {ff(97)}΅                   
   {ff(103)}΄{ff(133)}μ{ff(133)}Μ{ff(139)}΅{ff(103)}   {ff(103)} {ff(97)}ν{ff(103)}΅{ff(103)}΄ {ff(102)}   {ff(103)} {ff(103)}΄{ff(103)} {ff(103)} {ff(103)}΄{ff(103)} {ff(103)} {ff(102)} {ff(103)} {ff(103)}΄{ff(103)}΄{ff(103)} {ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(103)};{ff(133)}γ{ff(133)}Κ{ff(134)}Κ{ff(134)}Ν{ff(134)}Ν{ff(133)}΅{ff(103)} {ff(103)} {ff(102)}                              {ff(103)}   {ff(102)}                    
 {ff(102)} {ff(103)}΄{ff(102)}    {ff(102)} {ff(102)} {ff(103)}΄  {ff(102)}     {ff(102)} {ff(97)};{ff(97)};{ff(103)} {ff(102)} {ff(102)} {ff(102)} {ff(102)} {ff(102)}  {ff(102)} {ff(103)} {ff(102)} {ff(103)}  {ff(103)}΄{ff(133)}΅{ff(103)}΅{ff(103)}΄{ff(103)}΄{ff(102)}                                                           
           {ff(103)}΄    {ff(102)}΄{ff(103)}΄{ff(102)}    {ff(102)}  {ff(102)} {ff(103)}       {ff(102)}΅{ff(102)}΄{ff(102)}                                                              
            {ff(102)}             {ff(97)}΅          v{bold}{bright_red}{version}{blue}{{{green}#dev}}{reset}@{yellow}duty1g{reset}                                                                      
'''
    # Print banner with formatting applied - handle Windows encoding issues
    try:
        sys.stdout.buffer.write(head.encode('utf-8', errors='replace'))
        sys.stdout.buffer.write(b'\n')
        sys.stdout.buffer.flush()
    except Exception:
        try:
            print(head.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8', errors='replace'))
        except Exception:
            pass



class SubCat:
    """Enumerates subdomains and checks domain status and technologies."""

    def __init__(self,
                 domain: str,
                 output: Optional[str],
                 threads: int = 50,
                 scope: Optional[str] = None,
                 logger: object = None,
                 status_code: bool = False,
                 title: bool = False,
                 ip: bool = False,
                 up: bool = False,
                 tech: bool = False,
                 reverse: bool = False,
                 match_codes: Optional[List[int]] = None,
                 sources: Optional[List[str]] = None,
                 exclude_sources: Optional[List[str]] = None,
                 config: str = 'config.yaml',
                 use_cache: bool = True,
                 cache_ttl: int = 86400,
                 output_format: str = 'txt',
                 colors_enabled: bool = True,
                 silent: bool = False,
                 show_modules: bool = False):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.colors_enabled = colors_enabled
        self.silent = silent
        self.show_modules = show_modules
        self.match_codes = match_codes or []
        self.sources = sources
        self.exclude_sources = exclude_sources
        self.logger = logger
        self.status_code = status_code
        self.title = title
        self.ip = ip
        self.tech = tech
        self.up = up
        self.reverse = reverse
        self.output = output
        self.output_format = output_format.lower()

        self.found_domains = set()

        self.processed_domains = set()
        self.processed_results = []  # Store processed results for output
        self.lock = Lock()
        self.exit_event = threading.Event()
        self.scope = self._load_scope(scope) if scope else None


        # Reuse single Detector instance for all domains (performance optimization)
        self.detector = Detector(logger=self.logger, enable_tls_check=False) if self.tech else None
        self.output_writer = None
        self.display = None

        # Validate output format
        if self.output_format not in OutputFormatter.FORMATS:
            if self.logger:
                self.logger.warn(f"Unsupported output format: {self.output_format}. Using 'txt' instead.")
            self.output_format = 'txt'

        # Add appropriate extension to output file if specified
        if self.output:
            # Check if the output file already has an extension
            _, ext = os.path.splitext(self.output)
            # If no extension or different from the specified format, add the correct extension
            if not ext or ext[1:].lower() != self.output_format:
                self.output = f"{self.output}.{self.output_format}"
                if self.logger:
                    self.logger.debug(f"Added extension to output file: {self.output}")

            # Initialize streaming output writer
            include_fields = ['name']
            if self.ip:
                include_fields.append('ip')
            if self.status_code:
                include_fields.append('status')
            if self.title:
                include_fields.append('title')
            if self.tech:
                include_fields.append('technologies')

            metadata = {
                'domain': self.domain,
                'timestamp': time.time(),
                'settings': {
                    'status_code': self.status_code,
                    'title': self.title,
                    'ip': self.ip,
                    'up': self.up,
                    'tech': self.tech,
                    'reverse': self.reverse
                }
            }

            try:
                self.output_writer = StreamingOutputWriter(
                    self.output,
                    format_type=self.output_format,
                    metadata=metadata,
                    include_fields=include_fields
                )
                self.output_writer.open()
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to initialize output file: {e}")
                self.output_writer = None



        signal.signal(signal.SIGINT, self.signal_handler)

        if config is None:
            home = os.path.expanduser("~")
            default_config_path = os.path.join(home, ".subcat", "config.yaml")
            config_dir = os.path.dirname(default_config_path)
            os.makedirs(config_dir, exist_ok=True)
            if not os.path.exists(default_config_path):
                try:
                    with open(default_config_path, 'w') as f:
                        f.write(default_config)
                    self.logger.info(f"Default config created at: {dark_grey}{default_config_path}{reset}")
                except Exception as e:
                    self.logger.error(f"Failed to create default config: {e}")

            self.config = default_config_path
            self.logger.info(f"Using config: {dark_grey}{self.config}{reset}")
        else:
            self.config = config
            self.logger.info(f"Using config: {dark_grey}{self.config}{reset}")

    def signal_handler(self, signum, frame):
        """Handles shutdown signal."""
        self.exit_event.set()

        # Stop the display first to hide progress
        if self.display:
            try:
                self.display.stop()
            except Exception:
                pass

        self.logger.info("Shutting down gracefully...")

        # Close any live deep-detect browser BEFORE os._exit below: this handler
        # hard-exits and bypasses every finally block, so without this the
        # Playwright Node driver is left writing to a dead pipe and crashes
        # (EPIPE). shutdown_active_streamers() returns once it's cleanly closed.
        try:
            if __package__:
                from .screenshot import shutdown_active_streamers
            else:
                from screenshot import shutdown_active_streamers
            shutdown_active_streamers()
        except Exception:
            pass

        # Close output writer if open
        if self.output_writer:
            try:
                self.output_writer.close()
                self.logger.info(f"Output file finalized during shutdown: {self.output}")
            except Exception as e:
                self.logger.error(f"Error finalizing output file during shutdown: {e}")

        os._exit(1)

    @staticmethod
    def normalize_domain(domain: str) -> Optional[str]:
        """
        Normalize and sanitize a domain name.
        Removes invalid characters, trailing dots, and standardizes format.
        Returns None if domain becomes invalid after normalization.
        """
        if not domain:
            return None

        # Convert to lowercase and strip whitespace
        domain = domain.lower().strip()

        # Remove wildcards
        domain = domain.replace('*.', '')
        domain = domain.replace('*', '')

        # Remove trailing/leading dots
        domain = domain.strip('.')

        # Remove any whitespace within the domain
        domain = ''.join(domain.split())

        # Remove non-ASCII characters and invalid domain characters
        # Valid: a-z, 0-9, hyphen, dot
        normalized = ''
        for char in domain:
            if char.isalnum() or char in '.-':
                normalized += char

        domain = normalized

        # Remove multiple consecutive dots
        while '..' in domain:
            domain = domain.replace('..', '.')

        # Remove trailing/leading dots again
        domain = domain.strip('.')

        # Remove hyphens at start/end of labels
        labels = domain.split('.')
        cleaned_labels = []
        for label in labels:
            label = label.strip('-')
            if label:  # Only keep non-empty labels
                cleaned_labels.append(label)

        domain = '.'.join(cleaned_labels)

        # Validate the normalized domain
        if not domain or len(domain) > 253:
            return None

        # Check if domain has at least one dot (subdomain.domain.tld)
        if '.' not in domain:
            return None

        return domain

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validates whether the given string is a valid domain or subdomain."""
        pattern = re.compile(
            r'^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
        )
        return bool(pattern.match(domain))

    def _load_scope(self, scope_input: str) -> Set[str]:
        """Loads the IP scope list from a file or a direct IP/CIDR string."""
        self.logger.debug("Loading scope list")
        scope_ips = set()

        # Check if the scope_input is a file
        if os.path.exists(scope_input):
            try:
                with open(scope_input, 'r') as f:
                    lines = f.readlines()
            except Exception as e:
                self.logger.warn(f"Error loading scope file: {e}")
                return scope_ips

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    # For a /32 or any network with only one address, add that address
                    if network.num_addresses == 1:
                        scope_ips.add(str(network.network_address))
                    else:
                        scope_ips.update(str(ip) for ip in network.hosts())
                except ValueError as e:
                    self.logger.warn(f"Invalid network range in file: {line} - {e}")
        else:
            # Treat scope_input as a direct IP or CIDR string
            try:
                network = ipaddress.ip_network(scope_input, strict=False)
                if network.num_addresses == 1:
                    scope_ips.add(str(network.network_address))
                else:
                    scope_ips.update(str(ip) for ip in network.hosts())
            except ValueError as e:
                self.logger.warn(f"Invalid scope input: {scope_input} - {e}")

        return scope_ips

    def _validate_subdomain(self, subdomain: str) -> bool:
        """Validates the subdomain belongs to the target domain."""
        return self.domain in subdomain.lower()


        # Create a cache key based on module name, domain, and reverse mode
        cache_key = f"{module_name}:{self.domain}:{self.reverse}"

        # Check cache first if enabled
        if self.use_cache:
            cached_results = self.cache.get(cache_key)
            if cached_results is not None:
                self.logger.debug(f"✓ Cache hit for {module_name} ({len(cached_results)} cached)")
                # Normalize and validate cached results
                valid = []
                for s in cached_results:
                    normalized = self.normalize_domain(s)
                    if normalized and self._validate_subdomain(normalized):
                        valid.append(normalized)

                with self.lock:
                    # Use domain-module pairs for better deduplication
                    new_domains = []
                    for domain in valid:
                        pair = (domain, module_name)
                        if pair not in self.domain_module_pairs:
                            self.domain_module_pairs.add(pair)
                            if domain not in self.found_domains:
                                self.found_domains.add(domain)
                                new_domains.append(domain)

                # Return cached results (they'll be displayed by main loop)
                return new_domains

        try:
            if __package__:
                mod = importlib.import_module(f".modules.{module_name}", package=__package__)
            else:
                module_dir = pathlib.Path(__file__).parent / 'modules'
                spec = importlib.util.spec_from_file_location(module_name, str(module_dir / f"{module_name}.py"))
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

            results = mod.returnDomains(self.domain, self.logger, self.config, self.reverse, self.scope)

            # Cache the results if enabled
            if self.use_cache and results:
                self.cache.set(cache_key, results)

            # Normalize and validate results
            valid = []
            for s in results:
                normalized = self.normalize_domain(s)
                if normalized and self._validate_subdomain(normalized):
                    valid.append(normalized)

            with self.lock:
                # Use domain-module pairs for better deduplication
                new_domains = []
                for domain in valid:
                    pair = (domain, module_name)
                    if pair not in self.domain_module_pairs:
                        self.domain_module_pairs.add(pair)
                        if domain not in self.found_domains:
                            self.found_domains.add(domain)
                            new_domains.append(domain)
                return new_domains
        except Exception as e:
            self.logger.debug(f"Module {module_name} failed: {e}")
            return []



    def get_domain_status(self, domain: str) -> Dict:
        """
        Determines the domain status, protocol, response, and title.
        Uses httpx-like probing: tries both HTTP and HTTPS, prioritizing HTTPS.
        """
        info = {"protocol": None, "status": None, "response": None, "title": ""}

        with Navigator() as nav:
            # httpx-style probing: Try HTTPS first (most common), then HTTP
            # This is faster and more efficient than the old method

            # Try HTTPS first (80% of modern sites use HTTPS)
            https_result = None
            try:
                resp = nav.request(f"https://{domain}", method="GET", response_type="full", allow_redirects=True)
                https_result = {
                    "protocol": "https",
                    "status": resp.status_code,
                    "response": resp,
                    "url": str(resp.url)
                }
            except Exception as e:
                if hasattr(e, 'response') and e.response is not None:
                    https_result = {
                        "protocol": "https",
                        "status": e.response.status_code,
                        "response": e.response,
                        "url": str(e.response.url) if hasattr(e.response, 'url') else None
                    }

            # If HTTPS succeeded, use it
            if https_result and https_result["status"] is not None and str(https_result["status"]).upper() != "TIMEOUT":
                info["protocol"] = https_result["protocol"]
                info["status"] = https_result["status"]
                info["response"] = https_result["response"]
            else:
                # HTTPS failed or timed out, try HTTP
                try:
                    resp = nav.request(f"http://{domain}", method="GET", response_type="full", allow_redirects=True)
                    # Check if HTTP redirected to HTTPS
                    if str(resp.url).startswith("https://"):
                        info["protocol"] = "https"
                    else:
                        info["protocol"] = "http"
                    info["status"] = resp.status_code
                    info["response"] = resp
                except Exception as e:
                    if hasattr(e, 'response') and e.response is not None:
                        resp = e.response
                        info["protocol"] = "http"
                        info["status"] = resp.status_code
                        info["response"] = resp
                    else:
                        # Both protocols failed
                        info["status"] = None

            # Extract title if we have a valid response
            if info["response"] is not None:
                try:
                    info["title"] = nav._extract_title(info["response"]) or ""
                except Exception:
                    info["title"] = ""

        return info

    def _process_domain(self, domain: str, module: str = None, display=None) -> Optional[str]:
        """Processes a discovered subdomain."""
        if self.exit_event.is_set():
            return None
        with self.lock:
            if domain in self.processed_domains:
                return None
            self.processed_domains.add(domain)

        # Initialize result data structure for structured output
        result_data: Dict = {
            'name': domain,
            'ip': None,
            'status': None,
            'protocol': None,
            'title': None,
            'technologies': None,
            'is_alive': False
        }

        ip_address = None
        if self.ip or self.scope:
            try:
                ip_address = socket.gethostbyname(domain)
                result_data['ip'] = ip_address
            except socket.gaierror:
                ip_address = None

        if self.scope:
            if ip_address is None or ip_address not in self.scope:
                return None

        if self.status_code or self.title or self.tech or self.up:
            info = self.get_domain_status(domain)
            protocol = info["protocol"] if info["protocol"] else "http"
            status = info["status"]
            req = info["response"]
            title_text = info["title"]

            result_data['protocol'] = protocol
            result_data['status'] = status
            result_data['title'] = title_text
            result_data['is_alive'] = status is not None

            # If the domain is dead (status is None)
            result = ''
            if status is None:
                # Add dead domain to display counter (always count, but skip printing if --up)
                if display:
                    display.add_result(
                        domain,
                        module if module else 'unknown',
                        protocol=None,
                        status=status if self.status_code else None,
                        title=None,
                        ip=ip_address if self.ip else None,
                        technologies=None,
                        skip_print=self.up,  # Skip printing when --up flag is set
                        is_alive=False  # Dead domain
                    )

                # If --up flag is set, skip returning dead domains
                if self.up:
                    return None

                # Otherwise, show [DEAD] marker
                result = f"{domain} {red}[DEAD]{reset}"
                if self.ip and ip_address:
                    result += f" {blue}[{ip_address}]{reset}"
                # Add module source if provided and show_modules is enabled
                if module and self.show_modules:
                    result += f" {dark_grey}({module}){reset}"

                # Store the processed result data
                with self.lock:
                    self.processed_results.append(result_data)
                    # Write to output file in real-time if specified
                    if self.output_writer:
                        try:
                            self.output_writer.write_entry(result_data)
                        except Exception as e:
                            self.logger.error(f"Failed to write to output: {e}")

                return result

            # Otherwise, build the result as usual.
            result = f"{protocol}://{domain}"
            if self.status_code:
                def get_status_color(s):
                    try:
                        code = int(s)
                    except Exception:
                        return bright_red
                    if code in (200, 204):
                        return green
                    elif code in (301, 302, 307):
                        return blue
                    elif 400 <= code < 600:
                        return bright_red
                    else:
                        return yellow

                result += f" {get_status_color(status)}[{status}]{reset}"
            if self.title:
                result += f" {dark_grey}[{title_text[:30]}]{reset}"
            if self.tech and self.detector:
                try:
                    tech_list = self.detector.detect(domain, req)
                    if tech_list:
                        techs = ",".join(tech_list)
                        result += f" {yellow}[{techs}]{reset}"
                        result_data['technologies'] = tech_list
                except Exception as e:
                    self.logger.debug(f"Tech detection failed for {domain}: {e}")
        else:
            result = domain

        if self.ip and ip_address:
            result += f" {blue}[{ip_address}]{reset}"

        # Store the processed result data
        with self.lock:
            self.processed_results.append(result_data)
            # Write to output file in real-time if specified
            if self.output_writer:
                try:
                    self.output_writer.write_entry(result_data)
                except Exception as e:
                    self.logger.error(f"Failed to write to output: {e}")

        # Add to display for real-time output (only if domain passed all checks)
        if display:
            # Determine if domain is alive for counting purposes
            is_alive_status = result_data.get('is_alive', False)

            # Only display status if explicitly requested
            # Pass is_alive separately for counting without displaying status code
            display.add_result(
                domain,
                module if module else 'unknown',
                protocol=result_data.get('protocol') if self.up else None,
                status=result_data.get('status') if self.status_code else None,
                title=result_data.get('title') if self.title else None,
                ip=result_data.get('ip') if self.ip else None,
                technologies=result_data.get('technologies') if self.tech else None,
                is_alive=is_alive_status
            )

        # Add module source if provided and show_modules is enabled (for the returned result string)
        if module and self.show_modules:
            result += f" {dark_grey}({module}){reset}"

        return result





def argParserCommands():
    """Parses command-line arguments with subcommands."""

    class CapitalisedHelpFormatter(argparse.HelpFormatter):
        def add_usage(self, usage, actions, groups, prefix=None):
            if prefix is None:
                # Check if --no-colors is in sys.argv before parsing
                import sys
                colors_enabled = '--no-colors' not in sys.argv
                banner(colors_enabled=colors_enabled)
                prefix = 'Usage: '
            return super(CapitalisedHelpFormatter, self).add_usage(usage, actions, groups, prefix)

    # Main parser
    parser = argparse.ArgumentParser(
        prog='subcat',
        description='SubCat - Advanced Subdomain Enumeration Tool',
        add_help=False,
        formatter_class=CapitalisedHelpFormatter
    )

    # Main parser args (only -h here, rest goes in subparsers)
    parser.add_argument('-h', '--help', action='help', help="Show this help message and exit")

    # Create subparsers for modes
    subparsers = parser.add_subparsers(dest='mode', help='Enumeration mode')

    # ===== PASSIVE MODE (default) =====
    passive_parser = subparsers.add_parser('passive', help='Passive enumeration using APIs and passive sources (default)', formatter_class=CapitalisedHelpFormatter)

    # Input arguments
    passive_input = passive_parser.add_argument_group('INPUT')
    passive_input.add_argument('-d', '--domain', help="Target domain to scan (required if -l not provided)")
    passive_input.add_argument('-l', '--list', type=argparse.FileType('r'), help="File containing list of domains (required if -d not provided)")
    passive_input.add_argument('--scope', help="IP scope filter (IP or CIDR)")

    # Output arguments
    passive_output = passive_parser.add_argument_group('OUTPUT')
    passive_output.add_argument("-o", "--output", help="Output file")
    passive_output.add_argument('-of', '--output-format', choices=OutputFormatter.FORMATS, default='txt', help="Output format")
    passive_output.add_argument('-title', '--title', action='store_true', help="Show page titles")
    passive_output.add_argument('-ip', '--ip', action='store_true', help="Resolve IP addresses")
    passive_output.add_argument('-sc', '--status-code', dest='status_code', action='store_true', help="Show HTTP status codes")
    passive_output.add_argument('--up', action='store_true', help="Show only alive domains")
    passive_output.add_argument('-td', '--tech', action='store_true', help="Show detected technologies")
    passive_output.add_argument('-sm', '--show-modules', action='store_true', help="Show module names")

    # Screenshots
    passive_shots = passive_parser.add_argument_group('SCREENSHOTS')
    passive_shots.add_argument('-ss', '--screenshot', action='store_true', help="Capture screenshots of discovered subdomains (Playwright)")
    passive_shots.add_argument('-dd', '--deep-detect', action='store_true', help="Run detection in browser mode (renders JS, cookies, DOM) — pair with --tech/--title/--status-code. No screenshots")
    passive_shots.add_argument('--screenshot-dir', default=None, help="Directory for screenshots (default: ~/.subcat/screenshots)")
    passive_shots.add_argument('--screenshot-full', action='store_true', help="Capture full-page screenshots")
    passive_shots.add_argument('--screenshot-timeout', type=float, default=15.0, help="Per-page screenshot timeout in seconds (default: 15)")
    passive_shots.add_argument('--serve', action='store_true', help="Capture screenshots then open the report in a browser")
    passive_shots.add_argument('--serve-host', default='127.0.0.1', help="Report server host (default: 127.0.0.1)")
    passive_shots.add_argument('--serve-port', type=int, default=7171, help="Report server port (default: 7171)")

    # Filters
    passive_filters = passive_parser.add_argument_group('FILTERS')
    passive_filters.add_argument('-mc', '--match-codes', type=lambda s: [int(x.strip()) for x in s.split(',') if x.strip().isdigit()], default=[], help="Filter by status codes")

    # Sources
    passive_sources = passive_parser.add_argument_group('SOURCES')
    passive_sources.add_argument("-s", "--sources", type=lambda s: s.split(','), help="Specific sources to use (comma-separated)")
    passive_sources.add_argument("-es", "--exclude-sources", type=lambda s: s.split(','), help="Sources to exclude")
    passive_sources.add_argument("-r", "--reverse", action="store_true", help="Enable reverse lookup mode (requires --scope)")

    # Config
    passive_config = passive_parser.add_argument_group('CONFIGURATION')
    passive_config.add_argument('-t', '--threads', type=int, default=50, help="Number of threads (default: 50)")
    passive_config.add_argument('-c', '--config', help="Path to YAML config file (default: config.yaml)")
    passive_config.add_argument('--no-cache', action='store_true', help="Disable caching of results")
    passive_config.add_argument('--cache-ttl', type=int, default=86400, help="Cache TTL in seconds (default: 86400 = 24h)")
    passive_config.add_argument('--clear-cache', action='store_true', help="Clear all cached data before running")
    passive_config.add_argument("-ls", dest='list_modules', action="store_true", help="List available modules and exit")

    passive_debug = passive_parser.add_argument_group('DEBUG')
    passive_debug.add_argument('-v', '--verbose', action='count', default=0, help="Increase verbosity level (-v, -vv, -vvv)")
    passive_debug.add_argument('-silent', '--silent', action='store_true', help="Suppress all output except results")
    passive_debug.add_argument('-nc', '--no-colors', action='store_true', help="Disable colored output")

    # ===== BRUTE FORCE MODE =====
    brute_parser = subparsers.add_parser('brute', help='DNS brute force enumeration', formatter_class=CapitalisedHelpFormatter)

    brute_input = brute_parser.add_argument_group('INPUT')
    brute_input.add_argument('-d', '--domain', help="Target domain to scan (required if -l not provided)")
    brute_input.add_argument('-l', '--list', type=argparse.FileType('r'), help="File containing list of domains (required if -d not provided)")
    brute_input.add_argument('-w', '--wordlist', help="Wordlist file (default: built-in 100 common subdomains)")
    brute_input.add_argument('--scope', help="IP scope filter (IP or CIDR)")

    brute_output = brute_parser.add_argument_group('OUTPUT')
    brute_output.add_argument("-o", "--output", help="Output file")
    brute_output.add_argument('-of', '--output-format', choices=OutputFormatter.FORMATS, default='txt', help="Output format")
    brute_output.add_argument('-sc', '--status-code', dest='status_code', action='store_true', help="Show HTTP status codes")
    brute_output.add_argument('-title', '--title', action='store_true', help="Show page titles")
    brute_output.add_argument('-ip', '--ip', action='store_true', help="Resolve IP addresses")
    brute_output.add_argument('-td', '--tech', action='store_true', help="Show detected technologies")
    brute_output.add_argument('--up', action='store_true', help="Show only alive domains")
    brute_output.add_argument('-sm', '--show-modules', action='store_true', help="Show module names")

    # Screenshots
    brute_shots = brute_parser.add_argument_group('SCREENSHOTS')
    brute_shots.add_argument('-ss', '--screenshot', action='store_true', help="Capture screenshots of discovered subdomains (Playwright)")
    brute_shots.add_argument('-dd', '--deep-detect', action='store_true', help="Run detection in browser mode (renders JS, cookies, DOM) — pair with --tech/--title/--status-code. No screenshots")
    brute_shots.add_argument('--screenshot-dir', default=None, help="Directory for screenshots (default: ~/.subcat/screenshots)")
    brute_shots.add_argument('--screenshot-full', action='store_true', help="Capture full-page screenshots")
    brute_shots.add_argument('--screenshot-timeout', type=float, default=15.0, help="Per-page screenshot timeout in seconds (default: 15)")
    brute_shots.add_argument('--serve', action='store_true', help="Capture screenshots then open the report in a browser")
    brute_shots.add_argument('--serve-host', default='127.0.0.1', help="Report server host (default: 127.0.0.1)")
    brute_shots.add_argument('--serve-port', type=int, default=7171, help="Report server port (default: 7171)")

    # Filters
    brute_filters = brute_parser.add_argument_group('FILTERS')
    brute_filters.add_argument('-mc', '--match-codes', type=lambda s: [int(x.strip()) for x in s.split(',') if x.strip().isdigit()], default=[], help="Filter by status codes")

    brute_config = brute_parser.add_argument_group('CONFIGURATION')
    brute_config.add_argument('-t', '--threads', type=int, default=50, help="Number of threads (default: 50, recommended: 100-200)")
    brute_config.add_argument('-c', '--config', help="Path to YAML config file (default: config.yaml)")
    brute_config.add_argument('--timeout', type=float, default=10.0, help="HTTP timeout in seconds (default: 10)")

    brute_debug = brute_parser.add_argument_group('DEBUG')
    brute_debug.add_argument('-v', '--verbose', action='count', default=0, help="Increase verbosity level (-v, -vv, -vvv)")
    brute_debug.add_argument('-silent', '--silent', action='store_true', help="Suppress all output except results")
    brute_debug.add_argument('-nc', '--no-colors', action='store_true', help="Disable colored output")

    # ===== MONITOR MODE =====
    monitor_parser = subparsers.add_parser('monitor', help='Continuous subdomain monitoring', formatter_class=CapitalisedHelpFormatter)

    monitor_input = monitor_parser.add_argument_group('INPUT')
    monitor_input.add_argument('-d', '--domain', help="Target domain to monitor (required if -l not provided)")
    monitor_input.add_argument('-l', '--list', type=argparse.FileType('r'), help="File containing list of domains (required if -d not provided)")
    monitor_input.add_argument('--scope', help="IP scope filter (IP or CIDR)")

    monitor_output = monitor_parser.add_argument_group('OUTPUT')
    monitor_output.add_argument("-o", "--output", help="Output file for changes log")
    monitor_output.add_argument('-of', '--output-format', choices=OutputFormatter.FORMATS, default='txt', help="Output format")
    monitor_output.add_argument('-sc', '--status-code', dest='status_code', action='store_true', help="Show HTTP status codes")
    monitor_output.add_argument('-title', '--title', action='store_true', help="Show page titles")
    monitor_output.add_argument('-ip', '--ip', action='store_true', help="Resolve IP addresses")
    monitor_output.add_argument('-td', '--tech', action='store_true', help="Show detected technologies")
    monitor_output.add_argument('--up', action='store_true', help="Show only alive domains")
    monitor_output.add_argument('-sm', '--show-modules', action='store_true', help="Show module names")

    # Filters
    monitor_filters = monitor_parser.add_argument_group('FILTERS')
    monitor_filters.add_argument('-mc', '--match-codes', type=lambda s: [int(x.strip()) for x in s.split(',') if x.strip().isdigit()], default=[], help="Filter by status codes")

    monitor_config = monitor_parser.add_argument_group('CONFIGURATION')
    monitor_config.add_argument('--interval', type=int, default=3600, help="Monitoring interval in seconds (default: 3600)")
    monitor_config.add_argument('--iterations', type=int, help="Maximum iterations (default: infinite)")
    monitor_config.add_argument('-t', '--threads', type=int, default=50, help="Number of threads")
    monitor_config.add_argument('-c', '--config', help="Path to config file")
    monitor_config.add_argument("-s", "--sources", type=lambda s: s.split(','), help="Specific sources to use")
    monitor_config.add_argument("--no-cache", action='store_true', help="Disable caching")

    monitor_debug = monitor_parser.add_argument_group('DEBUG')
    monitor_debug.add_argument('-v', '--verbose', action='count', default=0, help="Increase verbosity level (-v, -vv, -vvv)")
    monitor_debug.add_argument('-silent', '--silent', action='store_true', help="Suppress all output except results")
    monitor_debug.add_argument('-nc', '--no-colors', action='store_true', help="Disable colored output")

    # ===== REPORT MODE =====
    report_parser = subparsers.add_parser('report', help='List or serve a screenshot scan by id', formatter_class=CapitalisedHelpFormatter)
    report_parser.add_argument('action', nargs='?', help="'serve <id>' to serve a scan, or 'list' to list scan ids")
    report_parser.add_argument('scan_id', nargs='?', help="Scan id to serve (see 'report --list')")
    report_parser.add_argument('-l', '--list', dest='list_ids', action='store_true', help="List all available scan ids")
    report_parser.add_argument('--host', default='127.0.0.1', help="Host to bind (default: 127.0.0.1)")
    report_parser.add_argument('-p', '--port', type=int, default=7171, help="Port to bind (default: 7171)")
    report_parser.add_argument('-nc', '--no-colors', action='store_true', help="Disable colored output")

    return parser


def run_screenshot_phase(hosts, args, logger, domain=None):
    """Capture screenshots for the given hosts and point the user at the report."""
    hosts = sorted({h.strip().lower() for h in hosts if h and h.strip()})
    if not hosts:
        logger.warn("No subdomains found to screenshot")
        return

    if __package__:
        from .screenshot import (Screenshotter, make_scan_id, write_scan_meta,
                                 default_base_dir, prune_scans_for_domain)
    else:
        from screenshot import (Screenshotter, make_scan_id, write_scan_meta,
                                default_base_dir, prune_scans_for_domain)

    # Each scan gets a unique id and its own sub-directory under the base dir,
    # which lives in the user's home (~/.subcat/screenshots) next to the cache.
    # The report server lists scans by id and serves any of them over its API.
    base_dir = getattr(args, 'screenshot_dir', None) or default_base_dir()
    scan_id = make_scan_id(domain or 'scan')
    outdir = os.path.join(base_dir, scan_id)
    logger.info(f"Capturing screenshots for {yellow}{len(hosts)}{reset} hosts "
                f"{dark_grey}(scan {scan_id}){reset}")

    # A screenshot is already a full browser render, so deep detection comes for
    # free — always fingerprint technologies during capture (the report UI shows
    # them). Screenshot implies deep-detect.
    detect_tech = True
    shotter = Screenshotter(
        output_dir=outdir,
        concurrency=min(getattr(args, 'threads', 50), 12),
        timeout=getattr(args, 'screenshot_timeout', 15.0),
        full_page=getattr(args, 'screenshot_full', False),
        detect_tech=detect_tech,
        logger=logger,
    )

    # Use a Rich progress bar (matching the scan's "Subdomains" bar) when we have
    # a colored TTY; otherwise fall back to a simple single-line counter.
    if __package__:
        from .display import RICH_AVAILABLE
    else:
        from display import RICH_AVAILABLE
    silent = getattr(args, 'silent', False)
    use_bar = (RICH_AVAILABLE and not silent
               and not getattr(args, 'no_colors', False)
               and sys.stderr.isatty())

    if use_bar:
        if __package__:
            from .display import TimestampColumn
        else:
            from display import TimestampColumn
        from rich.progress import (Progress, TextColumn, BarColumn,
                                   TaskProgressColumn, MofNCompleteColumn, TimeElapsedColumn)
        progress = Progress(
            TimestampColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            refresh_per_second=12,
        )
        task = progress.add_task("[yellow]Screenshots", total=len(hosts))

        def prog(done, total, ok):
            progress.update(task, completed=done,
                            description=f"[yellow]Screenshots [dim]({ok} alive)")

        with progress:
            results = shotter.run(hosts, progress_callback=prog)
            progress.update(task, total=len(hosts), completed=len(hosts),
                            description="[bold yellow]Screenshots")
    else:
        def prog(done, total, ok):
            logger.stdout(f"{green}{ok}{reset} alive / {done} done",
                          spinner='●', processed=str(done), total=str(total))

        results = shotter.run(hosts, progress_callback=prog)
        if not silent:
            sys.stdout.write('\n')
            sys.stdout.flush()

    if not results:
        return None

    write_scan_meta(outdir, domain, results)
    alive = sum(1 for r in results if r.get('status') is not None)
    logger.info(f"Captured {green}{alive}{reset}/{len(results)} screenshots {dark_grey}(scan {scan_id}){reset}")

    # Re-scanning a domain replaces its previous report: drop older scans for
    # the same domain so they don't pile up as duplicates.
    pruned = prune_scans_for_domain(base_dir, domain, scan_id)
    if pruned:
        logger.debug(f"Removed {pruned} older scan(s) for {domain}")

    # No static HTML is written — the report is served (and its data consumed)
    # from the report server's API. Show how to view this scan.
    logger.info(f"View report: {green}subcat report serve {scan_id}{reset}")
    return scan_id


def launch_report_server(args, logger, scan_ids=None):
    """Start the report server (and open the browser) after a --serve scan."""
    if __package__:
        from .report import serve as serve_report
        from .screenshot import default_base_dir
    else:
        from report import serve as serve_report
        from screenshot import default_base_dir

    base_dir = getattr(args, 'screenshot_dir', None) or default_base_dir()
    host = getattr(args, 'serve_host', '127.0.0.1')
    port = getattr(args, 'serve_port', 7171)

    # Serve only the scan we just produced when there's exactly one; with several
    # (a domain list) fall back to serving the whole base dir (scan list).
    only_scan = scan_ids[0] if scan_ids and len(scan_ids) == 1 else None

    serve_report(base_dir, host=host, port=port, logger=logger,
                 open_browser=True, only_scan=only_scan)


def print_mode_help(parser, mode):
    """Print the help for a specific subcommand (the banner is rendered by the
    shared formatter). Falls back to the top-level help if the mode is unknown."""
    if mode:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction) and mode in action.choices:
                action.choices[mode].print_help()
                return
    parser.print_help()


def main():
    try:
        # Default to passive mode when no subcommand is given so the old-style
        # `subcat -d example.com` keeps working. Bare invocation (no args) and
        # `-h/--help` still fall through to the top-level help.
        argv = sys.argv[1:]
        subcommands = ('passive', 'brute', 'monitor', 'report')
        if argv and argv[0] not in subcommands and argv[0] not in ('-h', '--help'):
            argv = ['passive'] + argv
        args = argParserCommands().parse_args(argv)

        # --screenshot/--serve implies deep detection: the browser pass that
        # screenshots also renders JS/cookies/DOM, so deep tech detection streams
        # during enumeration automatically (no need to also pass --deep-detect).
        if getattr(args, 'screenshot', False) or getattr(args, 'serve', False):
            args.deep_detect = True

        # Handle no-colors flag
        verbose = getattr(args, 'verbose', 0)
        if hasattr(args, 'no_colors') and args.no_colors:
            disable_all_colors()
            logger = Logger(level=verbose + 1, silent=getattr(args, 'silent', False), color=False)
        else:
            logger = Logger(level=verbose + 1, silent=getattr(args, 'silent', False))

        # Handle cache clearing if requested
        if hasattr(args, 'clear_cache') and args.clear_cache:
            cache = Cache()
            if cache.clear():
                logger.info("Cache cleared successfully")
            else:
                logger.error("Failed to clear cache")

        if hasattr(args, 'list_modules') and args.list_modules:
            banner(colors_enabled=not getattr(args, 'no_colors', False))
            try:
                if __package__:
                    module_dir = pkg_resources.files("subcat.modules")
                else:
                    module_dir = pathlib.Path(os.path.join(os.path.dirname(__file__), 'modules'))
            except Exception as e:
                logger.error(f"Error accessing subcat.modules resources: {e}")
                sys.exit(1)
            # Use the Traversable API to iterate over the files.
            modules = [
                f.name[:-3] for f in module_dir.iterdir()
                if f.name.endswith('.py') and f.name != '__init__.py'
            ]
            logger.info(f"{bold}{red}{len(modules)} {yellow}Available modules: {reset}")
            for module in modules:
                logger.result(f"{green}{module}{reset}")
            sys.exit(0)
        # If no mode specified, show help
        if not hasattr(args, 'mode') or args.mode is None:
            argParserCommands().print_help()
            sys.exit(0)

        # Report mode: serve the screenshot gallery (no domain required)
        if args.mode == 'report':
            # Bare `report` (no further args) shows its help.
            report_argv = sys.argv[sys.argv.index('report') + 1:] if 'report' in sys.argv else []
            if not report_argv:
                print_mode_help(argParserCommands(), 'report')
                sys.exit(0)

            banner(colors_enabled=not getattr(args, 'no_colors', False))
            if __package__:
                from .report import serve as serve_report
                from .screenshot import list_scans, default_base_dir
            else:
                from report import serve as serve_report
                from screenshot import list_scans, default_base_dir

            # Scans live under ~/.subcat/screenshots (next to the cache/config).
            base_dir = default_base_dir()
            action = getattr(args, 'action', None)

            # `report list` or `report -l/--list` → list scan ids and exit.
            if getattr(args, 'list_ids', False) or action == 'list':
                scans = list_scans(os.path.abspath(base_dir))
                if not scans:
                    logger.critical(f"No scans found in {red}{base_dir}{reset} "
                                    f"— run a scan with {yellow}--screenshot{reset} first")
                    sys.exit(1)
                logger.info(f"{yellow}{len(scans)}{reset} scan(s):")
                for s in scans:
                    created = f" {dark_grey}{s.get('created', '')}{reset}" if s.get('created') else ""
                    logger.result(f"  {green}{s['id']}{reset}  {s.get('domain', '')} "
                                  f"{dark_grey}({s.get('alive', 0)}/{s.get('total', 0)} alive){reset}{created}")
                sys.exit(0)

            # Serve a single scan by id: `report serve <id>` or `report <id>`.
            sid = getattr(args, 'scan_id', None)
            if action == 'serve':
                pass  # id is in scan_id
            elif action:
                sid = action  # `report <id>` shorthand
            if not sid:
                logger.critical(f"A scan id is required. Use {yellow}subcat report --list{reset} "
                                f"to see available scan ids, then {yellow}subcat report serve <id>{reset}")
                sys.exit(1)

            serve_report(base_dir, host=args.host, port=args.port, logger=logger,
                         only_scan=sid)
            sys.exit(0)

        # Validate reverse mode requirements
        if hasattr(args, 'reverse') and args.reverse and not hasattr(args, 'scope'):
            argParserCommands().print_help()
            logger.critical("Reverse lookup mode requires a scope IP or a file containing CIDR ranges (--scope)")
            sys.exit(1)

        # Get domain
        def show_header():
            if not getattr(args, 'silent', False):
                banner(colors_enabled=not getattr(args, 'no_colors', False))

        domain = None
        if hasattr(args, 'domain') and args.domain:
            show_header()
            if SubCat.is_valid_domain(args.domain):
                domain = args.domain.strip()
            else:
                logger.critical(f"Invalid domain: {red}{args.domain}{reset}")
                sys.exit(1)
        elif hasattr(args, 'list') and args.list:
            show_header()
            domains = [line.strip() for line in args.list if line.strip()]
        else:
            # No domain or list provided — show the proper help for this mode
            # (banner + usage), then the error in the standard log format.
            print_mode_help(argParserCommands(), getattr(args, 'mode', None))
            logger.critical("Please specify a domain with -d/--domain (or -l/--list)")
            sys.exit(1)

        # --- PASSIVE SCAN HELPER ---
        def execute_passive_scan(is_monitor=False, current_domain=None):
            active_domain = current_domain if current_domain else domain

            if __package__:
                from .passive import Passive
            else:
                from passive import Passive
                
            passive = Passive(
                domain=active_domain,
                sources=getattr(args, 'sources', None),
                exclude_sources=getattr(args, 'exclude_sources', None) if not is_monitor else None,
                reverse=getattr(args, 'reverse', False) if not is_monitor else False,
                scope=getattr(args, 'scope', None),
                config=getattr(args, 'config', None),
                use_cache=not getattr(args, 'no_cache', False),
                cache_ttl=getattr(args, 'cache_ttl', 86400) if not is_monitor else 86400,
                threads=getattr(args, 'threads', 50),
                logger=logger
            )
            
            if not is_monitor:
                logger.info(f"Starting enumeration for {red}{active_domain}{reset}")
                
            modules = passive._load_modules()
            if not is_monitor:
                logger.info(f"Loaded {yellow}{len(modules)}{reset} modules")
                
            display = create_display(
                active_domain,
                len(modules),
                colors_enabled=not getattr(args, 'no_colors', False),
                silent=getattr(args, 'silent', False),
                show_modules=not is_monitor and getattr(args, 'show_modules', False),
                show_alive_stats=getattr(args, 'up', False)
            )
            
            for mod in modules:
                display.add_module(mod)
                
            needs_processing = any([
                getattr(args, 'status_code', False),
                getattr(args, 'title', False),
                getattr(args, 'ip', False),
                getattr(args, 'tech', False),
                getattr(args, 'up', False),
                bool(getattr(args, 'match_codes', []))
            ])

            # Deep tech detection (Playwright) streams INTO the enumeration: each
            # discovered host is browser-probed as it is found, so detection runs
            # in the same pass instead of a separate trailing scan. It owns its
            # own browser, so the static processor is bypassed in this mode.
            # With --screenshot/--serve it still runs (deep tech shown inline as
            # hosts are found); the screenshot phase then follows on the live set.
            dt_mode = getattr(args, 'deep_detect', False)
            dt_streamer = None
            dt_results = []
            if dt_mode and not is_monitor:
                if __package__:
                    from .screenshot import _have_playwright
                else:
                    from screenshot import _have_playwright
                if not _have_playwright():
                    logger.critical("Playwright is not installed. Install it with: "
                                    f"{yellow}pip install playwright && playwright install chromium{reset}")
                    dt_mode = False

            processor = None
            if (needs_processing or getattr(args, 'output', None)) and not dt_mode:
                import signal
                original_sigint = signal.getsignal(signal.SIGINT)
                processor = SubCat(
                    domain=active_domain,
                    output=getattr(args, 'output', None) if not is_monitor else None,
                    threads=getattr(args, 'threads', 50),
                    scope=getattr(args, 'scope', None),
                    logger=logger,
                    status_code=getattr(args, 'status_code', False),
                    title=getattr(args, 'title', False),
                    ip=getattr(args, 'ip', False),
                    up=getattr(args, 'up', False),
                    tech=getattr(args, 'tech', False),
                    reverse=getattr(args, 'reverse', False) if not is_monitor else False,
                    match_codes=getattr(args, 'match_codes', []),
                    sources=getattr(args, 'sources', None),
                    exclude_sources=getattr(args, 'exclude_sources', None) if not is_monitor else None,
                    config=getattr(args, 'config', None),
                    use_cache=not getattr(args, 'no_cache', False),
                    cache_ttl=getattr(args, 'cache_ttl', 86400) if not is_monitor else 86400,
                    output_format=getattr(args, 'output_format', 'txt') if not is_monitor else 'txt',
                    colors_enabled=not getattr(args, 'no_colors', False),
                    silent=getattr(args, 'silent', False),
                    show_modules=getattr(args, 'show_modules', False)
                )
                signal.signal(signal.SIGINT, original_sigint)

            process_executor = ThreadPoolExecutor(max_workers=getattr(args, 'threads', 50)) if processor else None
            process_futures = []
            
            def module_started(mod_name):
                if hasattr(display, 'module_started'):
                    display.module_started(mod_name)
                
            def module_completed(mod_name, count):
                if hasattr(display, 'module_completed'):
                    display.module_completed(mod_name, count)
                
            def result_callback(subdomain, module_name):
                if hasattr(display, '_lock'):
                    with display._lock:
                        display.total_to_process += 1
                        if hasattr(display, 'subdomain_task_id') and display.subdomain_task_id is not None and hasattr(display, 'progress'):
                            display.progress.update(display.subdomain_task_id, total=display.total_to_process)
                elif hasattr(display, 'total_to_process'):
                    display.total_to_process += 1
                
                if dt_mode and dt_streamer is not None:
                    # Deep tech: hand the host to the browser streamer; results
                    # (status/title/tech) come back via dt_on_result.
                    dt_streamer.submit(subdomain)
                elif processor and process_executor:
                    future = process_executor.submit(processor._process_domain, subdomain, module_name, display)
                    process_futures.append(future)
                else:
                    display.add_result(
                        subdomain,
                        module_name,
                        protocol=None,
                        status=None,
                        title=None,
                        ip=None,
                        technologies=None,
                        is_alive=False
                    )

            # Deep tech streamer: browser-probe each host as it streams in from
            # enumeration. Results print inline in the live display.
            if dt_mode:
                if __package__:
                    from .screenshot import DeepTechStreamer
                else:
                    from screenshot import DeepTechStreamer

                # --deep-detect runs detection in browser mode; what is shown
                # still follows the normal flags (--status-code/--title/--tech).
                dt_want_status = getattr(args, 'status_code', False)
                dt_want_title = getattr(args, 'title', False)
                dt_want_tech = getattr(args, 'tech', False)

                def dt_on_result(entry):
                    status = entry.get('status')
                    is_alive = status is not None
                    dt_results.append(entry)
                    display.add_result(
                        entry.get('input'),
                        'deep-detect',
                        protocol=entry.get('protocol') if is_alive else None,
                        status=status if (dt_want_status and is_alive) else None,
                        title=entry.get('title') if dt_want_title else None,
                        ip=None,
                        technologies=entry.get('technologies') if dt_want_tech else None,
                        skip_print=not is_alive,  # browser probe: show live hosts
                        is_alive=is_alive,
                    )

                dt_streamer = DeepTechStreamer(
                    concurrency=min(getattr(args, 'threads', 50), 12),
                    timeout=getattr(args, 'screenshot_timeout', 15.0),
                    logger=logger,
                    on_result=dt_on_result,
                    detect_tech=dt_want_tech,
                )
                if not dt_streamer.start():
                    dt_streamer = None
                    dt_mode = False

            start_time = time.time()
            try:
                with display:
                    passive.run(module_started_callback=module_started, module_completed_callback=module_completed, result_callback=result_callback)

                    if dt_mode and dt_streamer is not None:
                        # All hosts discovered + submitted; drain the browser probes.
                        dt_streamer.close()

                    if processor and process_executor:
                        if not is_monitor:
                            logger.debug("Waiting for domain processing to complete...")
                        try:
                            for future in as_completed(process_futures):
                                try:
                                    future.result()
                                except Exception as e:
                                    logger.debug(f"Error processing domain: {e}")
                        except KeyboardInterrupt:
                            for future in process_futures:
                                future.cancel()
                            raise
                        finally:
                            process_executor.shutdown(wait=False)
                            if processor.output_writer:
                                try:
                                    processor.output_writer.close()
                                except Exception:
                                    pass
            finally:
                # Always tear the browser down (cancel in-flight probes on
                # Ctrl+C) so the Playwright driver subprocess exits cleanly.
                if dt_streamer is not None:
                    dt_streamer.close(drain=False)

            if not is_monitor:
                display.print_final_summary()
                
                end_time = time.time()
                elapsed = end_time - start_time
                minutes = int(elapsed // 60)
                seconds = int(elapsed % 60)
                milliseconds = int((elapsed % 1) * 1000)
                time_parts = []
                if minutes > 0:
                    time_parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
                if seconds > 0 or (minutes == 0 and milliseconds > 0):
                    time_parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
                if milliseconds > 0 or (minutes == 0 and seconds == 0):
                    time_parts.append(f"{milliseconds} millisecond{'s' if milliseconds != 1 else ''}")
                time_str = " ".join(time_parts)
                
                logger.info(f"Completed with {len(passive.found_domains)} subdomains for {red}{active_domain}{reset} in {time_str}")
                
                if not processor and hasattr(args, 'output') and args.output:
                    try:
                        with open(args.output, 'w') as f:
                            for d in passive.found_domains:
                                f.write(f"{d}\n")
                        logger.info(f"Results written to {args.output}")
                    except Exception as e:
                        logger.error(f"Failed to write output: {e}")
                        
            # Deep tech mode does its own (browser) liveness probing; surface
            # the live hosts when --up, otherwise all discovered subdomains.
            if dt_mode:
                if getattr(args, 'up', False):
                    return sorted({e.get('input') for e in dt_results
                                   if e.get('status') is not None})
                return list(passive.found_domains)

            # When --up is active (e.g. auto-enabled for --screenshot) surface only
            # the live hosts so the screenshot phase never shoots dead ones.
            if getattr(args, 'up', False) and processor is not None:
                with processor.lock:
                    alive = {r['name'] for r in processor.processed_results if r.get('is_alive')}
                return sorted(alive)
            return list(passive.found_domains)
        # --- END HELPER ---

        # Handle different modes
        if args.mode == 'brute':
            # Brute force mode
            if __package__:
                from .bruteforce import BruteForce
            else:
                from bruteforce import BruteForce

            # Handle list file if provided - process all domains
            target_domains = domains if 'domains' in locals() and domains else [domain]
            if len(target_domains) > 1:
                logger.info(f"Processing {len(target_domains)} domains from list file...")

            do_screenshot = getattr(args, 'screenshot', False) or getattr(args, 'serve', False)
            # Screenshots are only useful for live hosts, so auto-enable the up
            # probe and shoot the alive set only.
            if do_screenshot and not getattr(args, 'up', False):
                args.up = True
            scan_ids = []
            for domain_idx, target_domain in enumerate(target_domains, 1):
                if len(target_domains) > 1:
                    logger.info(f"{yellow}[{domain_idx}/{len(target_domains)}]{reset} Starting brute force mode for {red}{target_domain}{reset}")
                else:
                    logger.info(f"Starting {yellow}brute force{reset} mode for {red}{target_domain}{reset}")

                domain = target_domain

                brute = BruteForce(
                    domain=domain,
                    wordlist_file=getattr(args, 'wordlist', None),
                    threads=getattr(args, 'threads', 50),
                    logger=logger
                )

                # Create display for brute force - modules bar will show DNS progress
                display = create_display(
                    domain,
                    len(brute.wordlist),  # Total DNS checks to perform
                    colors_enabled=not getattr(args, 'no_colors', False),
                    silent=getattr(args, 'silent', False),
                    show_modules=False,
                    show_alive_stats=getattr(args, 'up', False)
                )

                results = []
                found_subdomains = []

                # Check if domain processing is needed
                needs_processing = any([
                    getattr(args, 'status_code', False),
                    getattr(args, 'title', False),
                    getattr(args, 'ip', False),
                    getattr(args, 'tech', False),
                    getattr(args, 'up', False),
                    bool(getattr(args, 'match_codes', []))
                ])

                # Deep tech detection streams into the brute pass (see passive
                # mode); when active it bypasses the static processor. Runs even
                # with --screenshot/--serve (screenshot phase follows after).
                dt_mode = getattr(args, 'deep_detect', False)
                dt_streamer = None
                dt_results = []
                if dt_mode:
                    if __package__:
                        from .screenshot import _have_playwright
                    else:
                        from screenshot import _have_playwright
                    if not _have_playwright():
                        logger.critical("Playwright is not installed. Install it with: "
                                        f"{yellow}pip install playwright && playwright install chromium{reset}")
                        dt_mode = False

                processor = None
                if needs_processing and not dt_mode:
                    import signal
                    original_sigint = signal.getsignal(signal.SIGINT)
                    processor = SubCat(
                        domain=domain,
                        output=getattr(args, 'output', None),
                        threads=getattr(args, 'threads', 50),
                        scope=getattr(args, 'scope', None),
                        logger=logger,
                        status_code=getattr(args, 'status_code', False),
                        title=getattr(args, 'title', False),
                        ip=getattr(args, 'ip', False),
                        up=getattr(args, 'up', False),
                        tech=getattr(args, 'tech', False),
                        match_codes=getattr(args, 'match_codes', []),
                        output_format=getattr(args, 'output_format', 'txt'),
                        colors_enabled=not getattr(args, 'no_colors', False),
                        silent=getattr(args, 'silent', False)
                    )
                    signal.signal(signal.SIGINT, original_sigint)

                # Progress callback to update display during DNS checking
                def dns_progress_callback(found_count, checked, total):
                    # Update modules progress bar to show DNS checking progress
                    if hasattr(display, 'task_id') and display.task_id is not None:
                        display.progress.update(
                            display.task_id,
                            completed=checked,
                            description=f"[cyan]Checking DNS [dim]({found_count} found)"
                        )

                process_executor = ThreadPoolExecutor(max_workers=getattr(args, 'threads', 50)) if needs_processing else None
                process_futures = []

                # Result callback to stream subdomains in real-time as they're found
                def result_callback(subdomain):
                    found_subdomains.append(subdomain)

                    # Update total subdomains to process for accurate progress bar
                    if hasattr(display, '_lock'):
                        with display._lock:
                            display.total_to_process += 1
                            if hasattr(display, 'subdomain_task_id') and display.subdomain_task_id is not None and hasattr(display, 'progress'):
                                display.progress.update(display.subdomain_task_id, total=display.total_to_process)
                    elif hasattr(display, 'total_to_process'):
                        display.total_to_process += 1

                    if dt_mode and dt_streamer is not None:
                        # Deep tech: browser-probe the host as it streams in.
                        dt_streamer.submit(subdomain)
                    elif needs_processing and process_executor:
                        # Submit for HTTP/HTTPS checking
                        future = process_executor.submit(processor._process_domain, subdomain, 'bruteforce', display)
                        process_futures.append(future)
                    else:
                        # Display subdomain immediately when found
                        display.add_result(
                            subdomain,
                            'bruteforce',
                            protocol=None,
                            status=None,
                            title=None,
                            ip=None,
                            technologies=None,
                            is_alive=False
                        )

                # Deep tech streamer: browser-probe each host as brute force
                # discovers it (single pass, results inline).
                if dt_mode:
                    if __package__:
                        from .screenshot import DeepTechStreamer
                    else:
                        from screenshot import DeepTechStreamer

                    # --deep-detect runs detection in browser mode; what is
                    # shown still follows the normal flags.
                    dt_want_status = getattr(args, 'status_code', False)
                    dt_want_title = getattr(args, 'title', False)
                    dt_want_tech = getattr(args, 'tech', False)

                    def dt_on_result(entry):
                        status = entry.get('status')
                        is_alive = status is not None
                        dt_results.append(entry)
                        display.add_result(
                            entry.get('input'),
                            'deep-detect',
                            protocol=entry.get('protocol') if is_alive else None,
                            status=status if (dt_want_status and is_alive) else None,
                            title=entry.get('title') if dt_want_title else None,
                            ip=None,
                            technologies=entry.get('technologies') if dt_want_tech else None,
                            skip_print=not is_alive,
                            is_alive=is_alive,
                        )

                    dt_streamer = DeepTechStreamer(
                        concurrency=min(getattr(args, 'threads', 50), 12),
                        timeout=getattr(args, 'screenshot_timeout', 15.0),
                        logger=logger,
                        on_result=dt_on_result,
                        detect_tech=dt_want_tech,
                    )
                    if not dt_streamer.start():
                        dt_streamer = None
                        dt_mode = False

                start_time = time.time()
                try:
                    with display:
                        # Run brute force with progress and result callbacks
                        brute.run(
                            progress_callback=dns_progress_callback,
                            result_callback=result_callback
                        )

                        # Mark DNS checking complete - remove modules progress bar
                        if hasattr(display, 'task_id') and display.task_id is not None and hasattr(display, 'progress'):
                            display.progress.update(
                                display.task_id,
                                completed=len(brute.wordlist),
                                description=f"[cyan]DNS Complete [green]({len(found_subdomains)} found)"
                            )
                            display.progress.remove_task(display.task_id)
                            display.module_progress_active = False

                        if dt_mode and dt_streamer is not None:
                            # All hosts discovered + submitted; drain browser probes.
                            dt_streamer.close()

                        if needs_processing and process_executor:
                            logger.debug("Waiting for domain processing to complete...")
                            try:
                                for future in as_completed(process_futures):
                                    try:
                                        future.result()
                                    except Exception as e:
                                        logger.debug(f"Error processing domain: {e}")
                            except KeyboardInterrupt:
                                for future in process_futures:
                                    future.cancel()
                                raise
                            finally:
                                process_executor.shutdown(wait=False)
                                if processor and processor.output_writer:
                                    try:
                                        processor.output_writer.close()
                                    except Exception:
                                        pass
                finally:
                    # Always tear the browser down (cancel in-flight probes on
                    # Ctrl+C) so the Playwright driver subprocess exits cleanly.
                    if dt_streamer is not None:
                        dt_streamer.close(drain=False)

                # Completion summary (printed after the live display closes so it
                # doesn't interleave with the progress bar).
                elapsed = time.time() - start_time
                minutes = int(elapsed // 60)
                seconds = int(elapsed % 60)
                milliseconds = int((elapsed % 1) * 1000)
                time_parts = []
                if minutes > 0:
                    time_parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
                if seconds > 0 or (minutes == 0 and milliseconds > 0):
                    time_parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
                if milliseconds > 0 or (minutes == 0 and seconds == 0):
                    time_parts.append(f"{milliseconds} millisecond{'s' if milliseconds != 1 else ''}")
                time_str = " ".join(time_parts)
                logger.info(f"Completed with {len(brute.found_subdomains)} subdomains for {red}{domain}{reset} in {time_str}")

                if do_screenshot:
                    # Only screenshot live hosts when the up probe ran.
                    shot_hosts = list(brute.found_subdomains)
                    if dt_mode:
                        # Deep detect did the (browser) liveness probing.
                        shot_hosts = sorted({e.get('input') for e in dt_results
                                             if e.get('status') is not None})
                    elif getattr(args, 'up', False) and processor is not None:
                        with processor.lock:
                            shot_hosts = sorted({r['name'] for r in processor.processed_results
                                                 if r.get('is_alive')})
                    sid = run_screenshot_phase(shot_hosts, args, logger, domain=domain)
                    if sid:
                        scan_ids.append(sid)
                # Deep detect (--deep-detect) is streamed inside the brute pass above,
                # so there is no separate phase here.

            if getattr(args, 'serve', False) and scan_ids:
                launch_report_server(args, logger, scan_ids)
        elif args.mode == 'monitor':
            # Monitoring mode
            if __package__:
                from .monitor import Monitor, format_monitoring_report
            else:
                from monitor import Monitor, format_monitoring_report
                
            target_domains = domains if 'domains' in locals() and domains else [domain]

            monitor = Monitor(domains=target_domains, logger=logger)

            # Define scan function for monitoring
            def run_scan(target_domain):
                return execute_passive_scan(is_monitor=True, current_domain=target_domain)

            # Check if domain processing is needed (same flags as passive/brute)
            is_silent = getattr(args, 'silent', False)
            monitor_needs_processing = any([
                getattr(args, 'status_code', False),
                getattr(args, 'title', False),
                getattr(args, 'ip', False),
                getattr(args, 'tech', False),
                getattr(args, 'up', False),
                bool(getattr(args, 'match_codes', []))
            ])

            # Notification callback
            def notify_changes(new_subs, stats):
                if not is_silent:
                    format_monitoring_report(new_subs, stats, logger)

                # Process new subdomains with --title, --up, -sc, etc.
                if new_subs and monitor_needs_processing:
                    monitor_processor = SubCat(
                        domain=stats.get('domain', domain),
                        output=None,
                        threads=getattr(args, 'threads', 50),
                        scope=getattr(args, 'scope', None),
                        logger=logger,
                        status_code=getattr(args, 'status_code', False),
                        title=getattr(args, 'title', False),
                        ip=getattr(args, 'ip', False),
                        up=getattr(args, 'up', False),
                        tech=getattr(args, 'tech', False),
                        match_codes=getattr(args, 'match_codes', []),
                        colors_enabled=not getattr(args, 'no_colors', False),
                        silent=is_silent
                    )
                    proc_executor = ThreadPoolExecutor(max_workers=getattr(args, 'threads', 50))
                    proc_futures = []
                    for sub in new_subs:
                        proc_futures.append(proc_executor.submit(monitor_processor._process_domain, sub, 'monitor'))
                    for future in as_completed(proc_futures):
                        try:
                            result = future.result()
                            if result:
                                print(result)
                        except Exception:
                            pass
                    proc_executor.shutdown(wait=False)
                elif is_silent:
                    # Silent mode without processing: just print new subdomains
                    for sub in new_subs:
                        print(sub)

                # Save to output file if specified
                if hasattr(args, 'output') and args.output and new_subs:
                    try:
                        with open(args.output, 'a') as f:
                            for sub in new_subs:
                                f.write(f"{sub}\n")
                    except Exception as e:
                        logger.error(f"Failed to write to output: {e}")

            # Start monitoring (monitor.watch() handles KeyboardInterrupt internally)
            monitor.watch(
                scan_function=run_scan,
                interval=getattr(args, 'interval', 3600),
                max_iterations=getattr(args, 'iterations', None),
                notify_callback=notify_changes
            )

        else:
            # Passive mode (default)
            target_domains = domains if 'domains' in locals() and domains else [domain]
            if len(target_domains) > 1:
                logger.info(f"Processing {yellow}{len(target_domains)}{reset} domains from list file...")
            do_screenshot = getattr(args, 'screenshot', False) or getattr(args, 'serve', False)
            # Screenshots are only useful for live hosts, so auto-enable the up
            # probe and shoot the alive set only.
            if do_screenshot and not getattr(args, 'up', False):
                args.up = True
            scan_ids = []
            for target_domain in target_domains:
                # Deep detect (--deep-detect) is streamed inside the scan
                # by execute_passive_scan, so there is no separate phase here.
                found = execute_passive_scan(is_monitor=False, current_domain=target_domain)
                if do_screenshot:
                    sid = run_screenshot_phase(found or [], args, logger, domain=target_domain)
                    if sid:
                        scan_ids.append(sid)
            if getattr(args, 'serve', False) and scan_ids:
                launch_report_server(args, logger, scan_ids)
    except KeyboardInterrupt:
        _shutdown_deep_detect_browsers()
        if getattr(args, 'silent', False):
            os._exit(0)
        logger.info("Shutting down gracefully...")
        os._exit(0)
    except Exception as e:
        if 'logger' not in locals():
            logger = Logger()
        logger.error(f"Fatal error: {e}")
        os._exit(1)


def _shutdown_deep_detect_browsers():
    """Close any live deep-detect browser before a hard os._exit (avoids the
    Playwright Node driver crashing with EPIPE on a half-closed pipe)."""
    try:
        if __package__:
            from .screenshot import shutdown_active_streamers
        else:
            from screenshot import shutdown_active_streamers
        shutdown_active_streamers()
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _shutdown_deep_detect_browsers()
        print("\nShutting down gracefully...")
        os._exit(0)
