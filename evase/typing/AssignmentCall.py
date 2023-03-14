
class AssignmentCall:
    def __init__(self, call, value):
        self.__value = value
        self.__call = call

    def get_value(self):
        return self.__value

    def get_call(self):
        return self.__call

    def __str__(self):
        return 'here'

    def __repr__(self):
        if self.__call == None:
            return self.__value
        elif self.__value == None:
            return self.__call+'()'
        return self.__value + '.' + self.__call+'()'