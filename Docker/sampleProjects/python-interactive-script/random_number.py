from random import randint

# Simple Python script asking for 2 integers a and b and returning a random integer in [a, b]
#
# It can run in a Docker container from an image based on the "python" image
#
# The input() command does not work if running the script in a non-interactive container
# To build the image and run the container in interactive mode, we use :
#    docker build -t my_python_image .
#    docker run -it --name my_python_container --rm my_python_image

min_number = int(input("Enter the min number: "))
max_number = int(input("Enter the max number: "))

if (max_number < min_number):
    print("Invalid input - shutting down...")
else:
    random_number = randint(min_number, max_number)
    print(f"Random number between {min_number} and {max_number} : {random_number}")
