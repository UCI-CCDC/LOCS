SRCS=coordinate.go ssher.go output.go

.PHONY: coordinate
coordinate: coordinate-linux coordinate-linux-32 coordinate-macos coordinate-windows.exe coordinate-windows-32.exe

coordinate-linux: $(SRCS)
	GOOS=linux GOARCH=amd64 go build -o $@

coordinate-linux-32: $(SRCS)
	GOOS=linux GOARCH=386 go build -o $@

coordinate-macos: $(SRCS)
	GOOS=darwin GOARCH=arm64 go build -o $@

coordinate-windows.exe: $(SRCS)
	GOOS=windows GOARCH=amd64 go build -o $@

coordinate-windows-32.exe: $(SRCS)
	GOOS=windows GOARCH=386 go build -o $@
