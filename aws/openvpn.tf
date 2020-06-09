provider "aws"{
   region = "sa-east-1"
   shared_credentials_file = "/home/eduabati/.aws/credentials"
   profile = "default"
}

resource "aws_instance" "example"{
   ami = "ami-0a8302bf9ba144bf1"
   instance_type = "t2.micro"   
   key_name = "${aws_key_pair.my-key.key_name}"
   security_groups = ["${aws_security_group.allow_ssh.name}"]
}

resource "aws_key_pair" "my-key" {
   key_name = "my-key01"
   public_key = "${file("id_rsa.pub")}"
}

resource "aws_security_group" "allow_ssh"{
   name = "allow_ssh"   
   ingress {
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
   }
   
   ingress {
      from_port = 9000
      to_port = 9000
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
   }
      
   egress {
      from_port = 0
      to_port = 0
      protocol = -1
      cidr_blocks = ["0.0.0.0/0"]
   }
}


output "example_public_dns"{
   value = "${aws_instance.example.public_dns}"
}
