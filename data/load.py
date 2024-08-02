import csv
import requests, io
import boto3

aws_bucket = "ccanime"

#used to upload dataset to dynamodb
def addAnime(anime, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('animelist4')
    table.put_item(Item=anime)
        
        
with open('animes.csv', 'r') as f:
    reader = csv.reader(f)
    id = 1
    for row in reader:
        if row[0] != "anime":
            genre = ""
            
            if (row[3] == "1"):
                genre += ", Action"
            if (row[4] == "1"):
                genre += ", Adventure"
            if (row[5] == "1"):
                genre += ", Comedy"
            if (row[6] == "1"):
                genre += ", Drama"
            if (row[7] == "1"):
                genre += ", Fantasy"
            if (row[8] == "1"):
                genre += ", Mystery"
            if (row[9] == "1"):
                genre += ", Romance"
            if (row[10] == "1"):
                genre += ", Sci-Fi"
            if (row[11] == "1"):
                genre += ", Shojo"
            if (row[12] == "1"):
                genre += ", Shonen"
            if (row[13] == "1"):
                genre += ", Slice of Life"
            if (row[14] == "1"):
                genre += ", Sports"
            if (row[15] == "1"):
                genre += ", Supernatural"
            if (row[16] == "1"):
                genre += ", Food"
                
            if genre != "":
                genre = genre[2:]
            
            if genre =="":
                genre = "Unknown"
            
            episodes = ""
            if row[2] == "0":
                episodes ="1"
            else:
                episodes = row[2]
            
            anime = {
                'anime_id':str(id),
                'name':row[0],
                'episodes':episodes,
                'url':"https://"+aws_bucket+".s3.amazonaws.com/"+str(id)+".jpg",
                'genre':genre,
                'rating':"0",
                'totalRating':"0",
                'votes' : "0"
            }
            addAnime(anime)
            print(id)
            id +=1

#used to upload images to s3
s3 = boto3.client('s3')
s3Resource = boto3.resource('s3', region_name='us-east-1')
        
with open('animes.csv', 'r') as f:
    reader = csv.reader(f)
    id = 1
    for row in reader:
        if row[0] != "anime":
            imageLink = requests.get(row[1])
            imageContent = io.BytesIO(imageLink.content)
            print(id)
            s3.upload_fileobj(imageContent, aws_bucket, str(id) + ".jpg")
            acl = s3Resource.ObjectAcl(aws_bucket, str(id) + ".jpg")
            acl.put(ACL='public-read')
            id +=1