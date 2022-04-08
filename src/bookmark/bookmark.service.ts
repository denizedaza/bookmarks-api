import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateBookmarkDto, EditBookmarkDto } from './dto';

@Injectable()
export class BookmarkService {
  constructor(private prisma: PrismaService) {}
  getBookmarks(userId: number) {
    return this.prisma.bookmark.findMany({
      where: { userId },
    });
  }

  getBookmarksById(userId: number, bookmarkId: number) {
    return this.prisma.bookmark.findFirst({
      where: { id: bookmarkId, userId },
    });
  }

  async createBookmark(userId: number, dto: CreateBookmarkDto) {
    const bookmark = await this.prisma.bookmark.create({
      data: {
        userId,
        ...dto,
      },
    });
    return bookmark;
  }

  async editBookmarkById(userId: number, bookmarkId: number, dto: EditBookmarkDto) {
    //get the bookmark from id
    const bookmark = await this.prisma.bookmark.findUnique({
      where: { 
        id: bookmarkId 
      },
    });
    
    // check if user owns the bookmark
    if (!bookmark || bookmark.userId !== userId) {
      throw new ForbiddenException('Access to bookmark is denied')
    }

    return this.prisma.bookmark.update({
      where: { 
        id: bookmarkId, 
      }, 
      data: { 
        ...dto
      }
    })
  }

  async deleteBookmarkById(userId: number, bookmarkId: number) {
     //get the bookmark from id
     const bookmark = await this.prisma.bookmark.findUnique({
      where: { 
        id: bookmarkId 
      },
    });
    
    // check if user owns the bookmark
    if (!bookmark || bookmark.userId !== userId) {
      throw new ForbiddenException('Access to bookmark is denied')
    }

    await this.prisma.bookmark.delete({
      where: {
        id: bookmarkId,
      }
    })
  }
}
