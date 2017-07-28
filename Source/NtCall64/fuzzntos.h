/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       FUZZNTOS.H
*
*  VERSION:     1.20
*
*  DATE:        28 July 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

void fuzz_ntos();

BOOL find_kiservicetable(
    ULONG_PTR           MappedImageBase,
    PRAW_SERVICE_TABLE  ServiceTable);
