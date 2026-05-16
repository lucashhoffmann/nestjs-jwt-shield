import { Controller, Get } from "@nestjs/common";
import { Public } from "nestjs-jwt-shield";

@Controller()
export class PublicController {
  @Public()
  @Get("public")
  getPublic() {
    return {
      message: "This route is public.",
    };
  }
}
