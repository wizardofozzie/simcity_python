def parseImageFromBlock(txn_outputs):
    '''Get yEnc encoded data from Blockchain and return binary file. '''
    # https://gist.github.com/shirriff/7461227133c26645abdf
    #
    # BTC Logo: (1) + (2)
    # 1) https://blockexplorer.com/tx/9173744691ac25f3cd94f35d4fc0e0a2b9d1ab17b4fe562acc07660552f95518
    # 2) https://blockexplorer.com/tx/ceb1a7fb57ef8b75ac59b56dd859d5cb3ab5c31168aa55eb3819cd5ddbd3d806
    r = ''
    for line in data:
        r += line.decode('hex')
    g = open('out.txt', 'wb')
    g.write(r)
    g.close()
    d = ''
    lines = r.split('\r\n')
    esc = 0
    for line in lines[1:]:
        if len(line) == 0: break
        for c in line:
            if c == '=' and esc != 1:
                esc = 1
                continue
            n = ord(c)
            if esc:
                c2 = chr((n-42-64+256)%256)
                esc = 0
            else:
                c2 = chr((n-42+256)%256)
            d += c2
    g = open('out.jpg', 'wb')
    g.write(d)
    g.close()
