#!/usr/bin/env python3

import readline

def __menu__main__interface(param):
    global currentConfigInterface
    if param.strip().isnumeric():
        currentConfigInterface = int(param)
        setMenu('inter', '$name$-int-' + str(currentConfigInterface) + '>')
    else:
        print("Usage is interface <num>.")

def __menu__inter__shutdown(param):
    global currentConfigInterface
    print("Shutting down interface " + str(currentConfigInterface))

def __menu__main__exit(param):
    quit()

def __menu__inter__exit(params):
    setMenu('main', '$name$> ')

def getPossibleCompletions(menu, enteredcmd):
    global CurrentMenu
    candidates = []
    menu = menu[2]

    cmd = enteredcmd.strip().split(' ')[0]

    for i in menu:
        if i == cmd:
            return [cmd]

        if i.startswith(cmd):
            candidates.append(i)

    return candidates


def readlineMenuCompleter(text, state):
    global CurrentMenu
    candidates = getPossibleCompletions(CurrentMenu, text)
    return candidates[state] if state < len(candidates) else None


readline.parse_and_bind("tab: complete")
readline.parse_and_bind("?: complete")
readline.set_completer(readlineMenuCompleter)
Name = 'coreswitch'

def runCommand(menu, cmd):
    global CurrentMenu
    candidates = getPossibleCompletions(menu, cmd)

    if len(candidates) == 0:
        print('No such command.')
    elif len(candidates) > 1:
        print('Possible commands:\n' + ', '.join(candidates))
    else:
        function = globals().get('__menu__' + CurrentMenu[0] + "__" + candidates[0], None)
        if function != None:
            params = cmd.partition(' ')[2]
            function(params)
        else:
            print('Not implemented.')


def setMenu(menu, ps0 = None):
    global CurrentMenu

    ps0 = ps0 if ps0 != None else menu

    entries = []

    for i in globals().keys():
        if i.startswith('__menu__' + menu + '__'):
            entries.append(i[10 + len(menu):])

    CurrentMenu = (menu, ps0, entries)

def PS0():
    global CurrentMenu
    return CurrentMenu[1].replace('$name$', Name)

def main():
    setMenu('main', '$name$> ')

    while True:
        command = ''
        
        while command.strip() == '':
            command = input(PS0())
        
        runCommand(CurrentMenu, command)


if __name__ == "__main__":
    main()