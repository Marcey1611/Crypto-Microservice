package com.projectwork.cryptoclient.cryptoclient.model;

public record IncomingMessage(String from, String jwt, String cipherText) {}
