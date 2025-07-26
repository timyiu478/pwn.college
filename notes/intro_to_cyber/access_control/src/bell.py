from pwn import *


levels = {
}


num_questions = int(input("Number of questions: "))

p = process("/challenge/run")

p.readuntil("the following Mandatory Access Control (MAC) system:\n")

num_levels = int(p.readuntil(" ").decode("utf-8").replace(" ", ""))
p.readline()

for l in reversed(range(num_levels)):
    level_code = p.readline().decode("utf-8").replace("\n", "")
    levels[level_code] = l

num_categories = int(p.readuntil(" ").decode("utf-8").replace(" ", ""))
p.readline()

for _ in range(num_categories):
    p.readline()

for i in range(num_questions):
    p.readuntil("Subject with level ")

    sub_level = p.readuntil(" and").decode("utf-8").replace(" and", "").replace(" ", "")

    p.readuntil("categories {")
    sub_categories = list(filter(lambda c : len(c) > 0, p.readuntil("}").decode("utf-8").replace("}", "").replace(" ", "").split(",")))

    operation = p.readuntil("an").decode("utf-8").replace("an", "").replace(" ", "")


    p.readuntil("Object with level ")
    obj_level = p.readuntil(" and").decode("utf-8").replace(" and", "").replace(" ", "")

    p.readuntil("categories {")
    obj_categories = list(filter(lambda c : len(c) > 0 , p.readuntil("}").decode("utf-8").replace("}", "").replace(" ", "").split(",")))

    print(sub_level, obj_level, operation, sub_categories, obj_categories)
    if operation == "read":
        if levels[sub_level] < levels[obj_level]:
            print("no")
            p.write("no"+"\n")
            continue
        ok = True
        for obj_cate in obj_categories:
            if obj_cate not in sub_categories:
                ok = False
                break
        if ok:
            print("yes")
            p.write("yes"+"\n")
        else:
            print("no")
            p.write("no"+"\n")
    elif operation == "write":
        if levels[sub_level] > levels[obj_level]:
            print("no")
            p.write("no"+"\n")
            continue
        ok = True
        for sub_cate in sub_categories:
            if sub_cate not in obj_categories:
                ok = False
                break
        if ok:
            print("yes")
            p.write("yes"+"\n")
        else:
            print("no")
            p.write("no"+"\n")

    print(i, p.readuntil("Correct!\n"))
    
print(p.readline())
print(p.readline())
print(p.readline())
