#!/bin/bash -ex
#
# A script to package only the necessary files of the extension.
#
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


echo "Building chrome extension"

./build_extension.sh

echo "Packaging chrome extension"

VERSION=$(egrep "\"version\":" manifest.json | cut -d\" -f4)
zip -r extension-"$VERSION".zip * -x extension-"$VERSION".zip \*.sh dialog.js package\* README.md node_modules/\* third_party/\* .git/\*

echo "Done"
