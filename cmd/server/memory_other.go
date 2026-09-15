//go:build !linux

package main

func configureTransparentHugePages() error { return nil }
