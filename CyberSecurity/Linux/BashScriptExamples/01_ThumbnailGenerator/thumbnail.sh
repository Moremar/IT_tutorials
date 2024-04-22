#!/usr/bin/env bash

# Program that generates a thumbnail for each .jpg file in a folder that is at least 100 pixels big
# and does not have a thumbnail yet
# Usage :    ./thumbnail.sh ./images


# ensure that the first argument is a valid images folder
image_folder=$1
if [[ ! -e $image_folder  || ! -d $image_folder ]] ; then
  echo "Invalid images folder : $image_folder" >&2
  exit 1
else
  echo "Generating a thumbnail for images smaller than 100px in folder $1"
fi

# generate a thumbnail for each image that is bigger than 100 pixels if not already generated
for image_file in "${image_folder}"/*.jpg ; do

  # skip thumbnail files
  if [[ $image_file == *.thumbnail.jpg ]] ; then
    echo " - skip thumbnail file $image_file"
    continue
  fi

  # skip image files that already have a thumbnail
  thumbnail_file="${image_file%.*}.thumbnail.jpg"
  if [[ -e $thumbnail_file ]] ; then
    echo " - skip file $image_file that already has a thumbnail"
    continue
  fi

  # skip image files smaller than 100x100
  image_width="$(identify -format "%w" "${image_file}")"
  image_height="$(identify -format "%h" "${image_file}")"
  if (( image_width < 100 && image_height < 100 )) ; then
    echo " - skip small image $image_file (size $image_width x $image_height)"
    continue
  fi

  # create the thumbnail image
  echo " - generate a thumbnail for image $image_file (size $image_width x $image_height)"
  convert "${image_file}" -resize 80x80 "${thumbnail_file}"

done