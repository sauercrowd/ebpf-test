def sort_list(list_to_sort):
    stack_l = list_to_sort
    stack_r = []
    tmp = None
    for i in range(len(list_to_sort)-1):
        for j in range(len(list_to_sort)-i-1):
            tmp = stack_l.pop()
            # element on top of the left smaller than in variable
            # variable has to go the left stack
            if stack_l[-1] < tmp:
                stack_r.append(stack_l.pop())
                stack_l.append(tmp)
            # element in the variable is smaller, so just
            # push to the right
            else:
                stack_r.append(tmp)
        # move stuff back
        for i in range(len(stack_r)):
            stack_l.append(stack_r.pop())
    return stack_l


print(sort_list([8, 1, 7, 2]))
